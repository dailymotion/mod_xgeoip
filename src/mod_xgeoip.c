/*
 * eXtended GeoIP Apache1 module
 * 2007/04 pyke@dailymotion.com
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

// Mandatory includes
#include <httpd.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_log.h>
#include <apr_base64.h>
#include <apr_md5.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include "mod_xgeoip.h"

// Defines
#define MODULE_VERSION              "1.13"

#define CONFIGURATION_ENABLE        "XGeoIP"
#define CONFIGURATION_MODE          "XGeoIPMode"
#define CONFIGURATION_COOKIE        "XGeoIPCookie"
#define CONFIGURATION_COOKIENAME    "XGeoIPCookieName"
#define CONFIGURATION_COOKIEDOMAIN  "XGeoIPCookieDomain"
#define CONFIGURATION_COOKIEKEY     "XGeoIPCookieKey"
#define CONFIGURATION_PROXYHEADER   "XGeoIPProxyHeader"
#define CONFIGURATION_PROXYLIST     "XGeoIPProxyList"
#define CONFIGURATION_DATABASE      "XGeoIPDatabases"

#define COOKIE_NAME                 "XGEOIP"
#define PROXY_HEADER                "X-Forwarded-For"

#define MODE_NONE                   (0)
#define MODE_NOTE                   (1)
#define MODE_ENV                    (2)

#define STRING_SIZE                 (512)
#define MAX_PROXY_ADDRESSES         (32)
#define MAX_DATABASES               (8)

#define DATABASE_UNKNOWN            (0)
#define DATABASE_COUNTRY            (1)
#define DATABASE_CITYREV0           (2)
#define DATABASE_CITYREV1           (3)
#define DATABASE_ASNUM              (4)
#define DATABASE_COUNTRY_BEGIN      (16776960)

// Pre-declarations
module AP_MODULE_DECLARE_DATA xgeoip_module;

// Lookup record
typedef struct
{
    int           initialized;
    unsigned int  remote;
    unsigned int  proxy;
    int           found;
    int           country_index;
    char          country_code2[3];
    char          country_code3[4];
    char          country_name[STRING_SIZE];
    char          continent_code[4];
    char          continent_name[STRING_SIZE];
    char          region_code[4];
    char          region_name[STRING_SIZE];
    char          city_name[STRING_SIZE];
    char          zip_code[STRING_SIZE];
    char          latitude[STRING_SIZE];
    char          longitude[STRING_SIZE];
    char          as_number[STRING_SIZE];
    char          as_name[STRING_SIZE];
} xgeoip_lookup;

// Configuration record
typedef struct
{
    int           initialized;
    int           enabled;
    int           mode;
    int           cookie_enabled;
    char          cookie_name[STRING_SIZE];
    char          cookie_domain[STRING_SIZE];
    char          cookie_key[STRING_SIZE];
    char          proxy_header[STRING_SIZE];
    int           proxy_count;
    unsigned int  proxy_list[MAX_PROXY_ADDRESSES][2];
    int           database_count;
    char          database_path[MAX_DATABASES][STRING_SIZE];
    int           database_size[MAX_DATABASES];
    char          database_date[MAX_DATABASES][STRING_SIZE];
    int           database_handle[MAX_DATABASES];
    int           database_type[MAX_DATABASES];
    int           database_segments[MAX_DATABASES];
    unsigned char *database_bits[MAX_DATABASES];
} xgeoip_configuration;

// Configuration record allocator
static void* xgeoip_create_configuration(apr_pool_t *pool, server_rec* server)
{
    xgeoip_configuration *configuration;

    configuration = apr_pcalloc(pool, sizeof(xgeoip_configuration));
    if(! configuration)
    {
        return NULL;
    }
    configuration->mode = MODE_NOTE | MODE_ENV;
    strncpy(configuration->cookie_name, COOKIE_NAME, sizeof(configuration->cookie_name) - 1);
    strncpy(configuration->proxy_header, PROXY_HEADER, sizeof(configuration->proxy_header) - 1);
    return configuration;
}

// Configuration record setter
static const char *xgeoip_set_configuration(cmd_parms *command, void *directory, const char *value)
{
    xgeoip_configuration *configuration;
    apr_finfo_t          finfo;
    apr_time_exp_t       time;
    char                 list[STRING_SIZE], *prefix, *token, *path, *last = NULL;
    unsigned int         mask, count;

    if(command->info == NULL || value == NULL)
    {
        return NULL;
    }
    configuration = ap_get_module_config(command->server->module_config, &xgeoip_module);
    if(! configuration)
    {
        return "XGeoIP Invalid configuration record";
    }
    if(! strcasecmp(command->info, CONFIGURATION_ENABLE))
    {
        configuration->enabled = (strcasecmp(value, "on") && strcasecmp(value, "yes")) ? 0 : 1;
    }
    else if(! strcasecmp(command->info, CONFIGURATION_MODE))
    {
        configuration->mode  = MODE_NONE;
        configuration->mode |= ! strcasecmp(value, "note") ? MODE_NOTE : configuration->mode;
        configuration->mode |= ! strcasecmp(value, "env") ? MODE_ENV : configuration->mode;
        configuration->mode |= ! strcasecmp(value, "both") ? MODE_NOTE | MODE_ENV : configuration->mode;
    }
    else if(! strcasecmp(command->info, CONFIGURATION_COOKIE))
    {
        configuration->cookie_enabled = (strcasecmp(value, "on") && strcasecmp(value, "yes")) ? 0 : 1;
    }
    else if(! strcasecmp(command->info, CONFIGURATION_COOKIENAME))
    {
        strncpy(configuration->cookie_name, value, sizeof(configuration->cookie_name) - 1);
    }
    else if(! strcasecmp(command->info, CONFIGURATION_COOKIEDOMAIN))
    {
        configuration->cookie_domain[0] = '.';
        strncpy(configuration->cookie_domain + (value[0] == '.' ? 0 : 1), value, sizeof(configuration->cookie_domain) - 2);
    }
    else if(! strcasecmp(command->info, CONFIGURATION_COOKIEKEY))
    {
        strncpy(configuration->cookie_key, value, sizeof(configuration->cookie_key) - 1);
    }
    else if(! strcasecmp(command->info, CONFIGURATION_PROXYHEADER))
    {
        strncpy(configuration->proxy_header, value, sizeof(configuration->proxy_header) - 1);
    }
    else if(! strcasecmp(command->info, CONFIGURATION_PROXYLIST))
    {
        strncpy(list, value, sizeof(list) - 1);
        prefix = strtok_r(list, " \t", &last);
        while(prefix && configuration->proxy_count < MAX_PROXY_ADDRESSES)
        {
            mask = 32;
            if((token = strchr(prefix, '/')))
            {
                *token = 0;
                mask = atoi(token + 1);
                if(mask > 32 || mask < 1)
                {
                    mask = 32;
                }
            }
            configuration->proxy_list[configuration->proxy_count][0] = inet_addr(prefix);
            if(configuration->proxy_list[configuration->proxy_count][0] != INADDR_NONE)
            {
                configuration->proxy_list[configuration->proxy_count][1] = 0xffffffff;
                for(count = 31; count > (mask - 1); count --)
                {
                     configuration->proxy_list[configuration->proxy_count][1] &= ~(1 << count);
                }
                configuration->proxy_count ++;
            }
            prefix = strtok_r(NULL, " \t", &last);
        }
    }
    else if(! strcasecmp(command->info, CONFIGURATION_DATABASE))
    {
        strncpy(list, value, sizeof(list) - 1);
        path = strtok_r(list, " \t", &last);
        while(path && configuration->database_count < MAX_DATABASES)
        {
            if(apr_stat(&finfo, path, APR_FINFO_NORM, command->temp_pool) != APR_SUCCESS)
            {
                return "XGeoIP Cannot stat database path specified for the " CONFIGURATION_DATABASE " directive";
            }
            if(finfo.filetype != APR_REG)
            {
                return "XGeoIP Parameter specified for the " CONFIGURATION_DATABASE " directive is not a valid file";
            }
            strncpy(configuration->database_path[configuration->database_count], path, sizeof(configuration->database_path[configuration->database_count]) - 1);
            apr_time_exp_lt(&time, finfo.mtime);
            sprintf(configuration->database_date[configuration->database_count],
                    "%04d-%02d-%02d", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday);
            configuration->database_size[configuration->database_count] = finfo.size;
            configuration->database_count ++;
            path = strtok_r(NULL, " \t", &last);
       }
    }
    return NULL;
}

// Configuration commands grammar
static const command_rec xgeoip_cmds[] =
{
    AP_INIT_TAKE1(CONFIGURATION_ENABLE,       xgeoip_set_configuration, CONFIGURATION_ENABLE,       RSRC_CONF, "Enable module"),
    AP_INIT_TAKE1(CONFIGURATION_MODE,         xgeoip_set_configuration, CONFIGURATION_MODE,         RSRC_CONF, "Set information passing mode"),
    AP_INIT_TAKE1(CONFIGURATION_COOKIE,       xgeoip_set_configuration, CONFIGURATION_COOKIE,       RSRC_CONF, "Enable information caching cookie"),
    AP_INIT_TAKE1(CONFIGURATION_COOKIENAME,   xgeoip_set_configuration, CONFIGURATION_COOKIENAME,   RSRC_CONF, "Set information caching cookie name"),
    AP_INIT_TAKE1(CONFIGURATION_COOKIEDOMAIN, xgeoip_set_configuration, CONFIGURATION_COOKIEDOMAIN, RSRC_CONF, "Set information caching cookie domain name"),
    AP_INIT_TAKE1(CONFIGURATION_COOKIEKEY,    xgeoip_set_configuration, CONFIGURATION_COOKIEKEY,    RSRC_CONF, "Set information caching cookie security key"),
    AP_INIT_TAKE1(CONFIGURATION_PROXYHEADER,  xgeoip_set_configuration, CONFIGURATION_PROXYHEADER,  RSRC_CONF, "Set proxy(ies) originating IP header name"),
    AP_INIT_TAKE1(CONFIGURATION_PROXYLIST,    xgeoip_set_configuration, CONFIGURATION_PROXYLIST,    RSRC_CONF, "Set proxy(ies) authorized source address(es)"),
    AP_INIT_TAKE1(CONFIGURATION_DATABASE,     xgeoip_set_configuration, CONFIGURATION_DATABASE,     RSRC_CONF, "Set databases paths"),
    {NULL}
};

// Global cleanup
static int xgeoip_cleanup(void *parameter)
{
  xgeoip_configuration *configuration = (xgeoip_configuration *)parameter;
  int                  count;

  for(count = 0; count < configuration->database_count; configuration ++)
  {
       if(configuration->database_bits[count])
       {
           munmap(configuration->database_bits[count], configuration->database_size[count]);
       }
       if(configuration->database_handle[count] > 0)
       {
           close(configuration->database_handle[count]);
       }
  }
  return 0;
}

// Global initialization
static int xgeoip_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
    void                 *initialized = NULL;
    const char           *key         = "xgeoip_double_startup_mutex";
    xgeoip_configuration *configuration;
    int                  offset, count;

    apr_pool_userdata_get(&initialized, key, server->process->pool);
    if(! initialized)
    {
        apr_pool_userdata_set((const void *)1, key, apr_pool_cleanup_null, server->process->pool);
        return OK;
    }
    configuration = ap_get_module_config(server->module_config, &xgeoip_module);
    if(! configuration)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "XGeoIP Invalid configuration record - module disabled");
        return OK;
    }
    if(!configuration->enabled || configuration->initialized)
    {
        return OK;
    }
    for(count = 0; count < configuration->database_count; count ++)
    {
         configuration->database_handle[count] = open(configuration->database_path[count], O_RDONLY);
         if(configuration->database_handle[count] < 0)
         {
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "XGeoIP Cannot open database %s - module disabled", configuration->database_path[count]);
             return OK;
         }
         configuration->database_bits[count] = mmap(0, configuration->database_size[count], PROT_READ, MAP_SHARED, configuration->database_handle[count], 0);
         if(configuration->database_bits[count] == MAP_FAILED)
         {
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "XGeoIP Cannot map database %s into memory - module disabled", configuration->database_path[count]);
             return OK;
         }
         for(offset = configuration->database_size[count] - 3; offset > configuration->database_size[count] - 23; offset --)
         {
             if(configuration->database_bits[count][offset] == 0xff &&
                configuration->database_bits[count][offset + 1] == 0xff && 
                configuration->database_bits[count][offset + 2] == 0xff)
             {
                 if(configuration->database_bits[count][offset + 3] == 2 || 
                    configuration->database_bits[count][offset + 3] == 111 ||
                    configuration->database_bits[count][offset + 3] == 9)
                 {
                     switch(configuration->database_bits[count][offset + 3])
                     {
                         case 9:
                              configuration->database_type[count] = DATABASE_ASNUM;
                              break;

                         case 2:
                              configuration->database_type[count] = DATABASE_CITYREV1;
                              break;

                         case 111:
                              configuration->database_type[count] = DATABASE_CITYREV0;
                              break;

                     }
                     configuration->database_segments[count] = configuration->database_bits[count][offset + 4] +
                                                               (configuration->database_bits[count][offset + 5] << 8) +
                                                               (configuration->database_bits[count][offset + 6] << 16);
                 }
                 break;
             }
         }
         if(offset == configuration->database_size[count] - 23)
         {
             configuration->database_type[count]     = DATABASE_COUNTRY;
             configuration->database_segments[count] = DATABASE_COUNTRY_BEGIN;
         }
         if(configuration->database_type[count] == DATABASE_UNKNOWN)
         {
             ap_log_error(APLOG_MARK, APLOG_ERR, 0, server, "XGeoIP Incompatible database %s - module disabled", configuration->database_path[count]);
             return OK;
         }
    }
    configuration->initialized = 1;
    apr_pool_cleanup_register(pconf, (void *)configuration, xgeoip_cleanup, apr_pool_cleanup_null);
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "XGeoIP Version %s started (%d databases loaded)", MODULE_VERSION, configuration->database_count);
    for(count = 0; count < configuration->database_count; count ++)
    {
         ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "XGeoIP Using database %s (%s edition - %d bytes - %d segments)",
                      configuration->database_path[count],
                      (configuration->database_type[count] == DATABASE_ASNUM) ? "ASNUM" : (configuration->database_type[count] == DATABASE_COUNTRY) ? "COUNTRY" : "CITY",
                      configuration->database_size[count],
                      configuration->database_segments[count]);
    }
    return OK;
}

// Initialize lookup record
static int xgeoip_lookup_init(request_rec *request, const xgeoip_configuration *configuration, xgeoip_lookup *lookup, char *address)
{
    unsigned int remote;
    int          count;
    const char   *header;

    if(request == NULL || configuration == NULL || !configuration->enabled || !configuration->initialized || lookup == NULL)
    {
        return 0;
    }
    memset(lookup, 0, sizeof(xgeoip_lookup));
    strcpy(lookup->latitude,  "0.0000000000000");
    strcpy(lookup->longitude, "0.0000000000000");
    if(address != NULL)
    {
        lookup->remote = inet_addr(address);
    }
    else
    {
        lookup->remote = inet_addr(request->connection->remote_ip);
        if(configuration->proxy_header[0])
        {
            header = apr_table_get(request->headers_in, configuration->proxy_header);
            if(header)
            {
                remote = inet_addr(header);
                if(remote != INADDR_NONE)
                {
                    if(configuration->proxy_count > 0)
                    {
                        for(count = 0; count < configuration->proxy_count; count ++)
                        {
                             if((configuration->proxy_list[count][0] & configuration->proxy_list[count][1]) == (lookup->remote & configuration->proxy_list[count][1]))
                             {
                                 break;
                             }
                        }
                        if(count < configuration->proxy_count)
                        {
                            lookup->proxy  = lookup->remote;
                            lookup->remote = remote;
                        }
                    }
                    else
                    {
                        lookup->proxy  = lookup->remote;
                        lookup->remote = remote;
                    }
                }
            }
        }
    }
    return 1;
}

// Lookup from database
static int xgeoip_lookup_from_database(const xgeoip_configuration *configuration, int count, xgeoip_lookup *lookup)
{
    unsigned char *pointer;
    unsigned int  remote;
    int           depth, offset = 0, position = 0, region = 0;

    if(configuration == NULL || !configuration->enabled || !configuration->initialized || lookup == NULL)
    {
        return 0;
    }
    remote = (lookup->remote >> 24) + ((lookup->remote >> 8) & 0xff00) + ((lookup->remote << 8) & 0xff0000) + ((lookup->remote << 24) & 0xff000000);
    for(depth = 31; depth >= 0; depth --)
    {
         if((6 * offset) > (configuration->database_size[count] - 6))
         {
             return 0;
         }
         pointer = configuration->database_bits[count] + (6 * offset);
         if(remote & (1 << depth))
         {
             position = pointer[3] + (pointer[4] << 8) + (pointer[5] << 16);
         }
         else
         {
             position = pointer[0] + (pointer[1] << 8) + (pointer[2] << 16);
         }
         if(position >= configuration->database_segments[count])
         {
             if(position == configuration->database_segments[count])
             {
                 return 0;
             }
             if(configuration->database_type[count] == DATABASE_ASNUM)
             {
                 offset = position + (5 * configuration->database_segments[count]);
                 if(offset > configuration->database_size[count] - 300)
                 {
                     return 0;
                 }
                 position = 0;
                 do
                 {
                     if(position < (sizeof(lookup->as_number) - 1))
                     {
                         lookup->as_number[position ++] = configuration->database_bits[count][offset];
                     }
                     offset ++;
                 } while(configuration->database_bits[count][offset] && configuration->database_bits[count][offset] != ' ');
                 if(configuration->database_bits[count][offset] == ' ')
                 {
                     offset ++;
                     position = 0;
                     do
                     {
                         if(position < (sizeof(lookup->as_name) - 1))
                         {
                             lookup->as_name[position ++] = configuration->database_bits[count][offset];
                         }
                     } while(configuration->database_bits[count][offset ++]);
                 }
             }
             else if (configuration->database_type[count] == DATABASE_CITYREV1)
             {
                 offset = position + (5 * configuration->database_segments[count]);
                 if(offset > configuration->database_size[count] - 50)
                 {
                     return 0;
                 }
                 lookup->country_index = configuration->database_bits[count][offset];
                 if(lookup->country_index < 0 || lookup->country_index > MAX_COUNTRIES)
                 {
                     return 0;
                 }
                 strcpy(lookup->country_code2, xgeoip_countries_codes2[lookup->country_index]);
                 strcpy(lookup->country_code3, xgeoip_countries_codes3[lookup->country_index]);
                 strcpy(lookup->country_name, xgeoip_countries_names[lookup->country_index]);
                 strcpy(lookup->continent_code, xgeoip_continents_codes[lookup->country_index]);
                 if(lookup->continent_code[count])
                 {
                     position = 0;
                     while(xgeoip_continents_names[position] &&
                           strcmp(xgeoip_continents_names[position], lookup->continent_code))
                     {
                         position += 2;
                     }
                     if(xgeoip_continents_names[position])
                     {
                         strncpy(lookup->continent_name, xgeoip_continents_names[position + 1], sizeof(lookup->continent_name) - 1);
                     }
                 }
                 offset ++;
                 position = 0;
                 do
                 {
                     if(position < (sizeof(lookup->region_code) - 1))
                     {
                         lookup->region_code[position ++] = configuration->database_bits[count][offset];
                     }
                 } while(configuration->database_bits[count][offset ++]);
                 if(lookup->region_code[count])
                 {
                     position = 0;
                     while(xgeoip_regions_names[position].country_code &&
                           strcmp(xgeoip_regions_names[position].country_code, lookup->country_code2))
                     {
                         position ++;
                     }
                     if(xgeoip_regions_names[position].country_code)
                     {
                         region = 0;
                         while(xgeoip_regions_names[position].regions[region].region_code && 
                               strcmp(xgeoip_regions_names[position].regions[region].region_code, lookup->region_code))
                         {
                             region ++;
                         }
                         if(xgeoip_regions_names[position].regions[region].region_code)
                         {
                             strncpy(lookup->region_name, xgeoip_regions_names[position].regions[region].region_name, sizeof(lookup->region_name) - 1);
                         }
                     }
                 }
                 position = 0;
                 do
                 {
                     if(position < (sizeof(lookup->city_name) - 1))
                     {
                         lookup->city_name[position ++] = configuration->database_bits[count][offset];
                     }
                 } while(configuration->database_bits[count][offset ++]);
                 position = 0;
                 do
                 {
                     if(position < (sizeof(lookup->zip_code) - 1))
                     {
                         lookup->zip_code[position ++] = configuration->database_bits[count][offset];
                     }
                 } while(configuration->database_bits[count][offset ++]);
                 position = configuration->database_bits[count][offset] + (configuration->database_bits[count][offset + 1] << 8) + (configuration->database_bits[count][offset + 2] << 16);
                 snprintf(lookup->latitude, sizeof(lookup->latitude) - 1, "%3.13f", ((double)position / 10000) - 180);
                 offset += 3;
                 position = configuration->database_bits[count][offset] + (configuration->database_bits[count][offset + 1] << 8) + (configuration->database_bits[count][offset + 2] << 16);
                 snprintf(lookup->longitude, sizeof(lookup->longitude) - 1, "%3.13f", ((double)position / 10000) - 180);
                 lookup->found = 1;
                 return 1;
             }
             else
             {
                 lookup->country_index = position - DATABASE_COUNTRY_BEGIN;
                 if(lookup->country_index < 0 || lookup->country_index > MAX_COUNTRIES)
                 {
                     return 0;
                 }
                 strcpy(lookup->country_code2, xgeoip_countries_codes2[lookup->country_index]);
                 strcpy(lookup->country_code3, xgeoip_countries_codes3[lookup->country_index]);
                 strcpy(lookup->country_name, xgeoip_countries_names[lookup->country_index]);
                 strcpy(lookup->continent_code, xgeoip_continents_codes[lookup->country_index]);
                 lookup->found = 1;
                 return 1;
             }
             return 0;
         }
         offset = position;
    }
    return 0;
}

// Fill lookup structure from cookie
static int xgeoip_lookup_from_cookie(xgeoip_configuration *configuration, const char *input, xgeoip_lookup *lookup)
{
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char          cookies[STRING_SIZE], key[STRING_SIZE], *cookie, *last, *field;
    int           count, cookie_length;
    unsigned int  address;

    if(configuration == NULL || !configuration->enabled || !configuration->initialized || input == NULL || lookup == NULL)
    {
        return 0;
    }
    lookup->found = 0;
    memset(cookies, 0, sizeof(cookies));
    strncpy(cookies, input, sizeof(cookies) - 1);
    cookie_length = strlen(configuration->cookie_name);
    cookie = strtok_r(cookies, " ;", &last);
    while(cookie)
    {
        if(! strncasecmp(cookie, configuration->cookie_name, cookie_length))
        {
            break;
        }
        cookie = strtok_r(NULL, " ;", &last);
    }
    if(! cookie || cookie[cookie_length] != '=')
    {
        return 0;
    }
    cookie += cookie_length + 1;
    if(configuration->cookie_key[0] != 0)
    {
        if(strlen(cookie) < 17)
        {
            return 0;
        }
        memset(key, 0, sizeof(key));
        if(snprintf(key, sizeof(key) - 1, "%s%s", cookie + 17, configuration->cookie_key) >= (sizeof(key) - 1))
        {
            return 0;
        }
        if(apr_md5(digest, key, strlen(key)))
        {
            return 0;
        }
        for(count = 0; count < 8; count ++)
        {
             key[(count * 2)]     = ((digest[count] >> 4) <= 9) ? '0' + (digest[count] >> 4): 'a' + (digest[count] >> 4) - 10;
             key[(count * 2) + 1] = ((digest[count] & 0x0f) <= 9) ? '0' + (digest[count] & 0x0f) : 'a' + (digest[count] & 0x0f) - 10;
        }
        key[16] = 0;
        if(memcmp(cookie, key, 16))
        {
            return 0;
        }
        cookie += 17;
    }
    field = strtok_r(cookie, ":", &last);
    while(field)
    {
        switch(field[0])
        {
            case 'I':
                 if(sscanf(field + 1, "%08x", &address) != 1)
                 {
                     return 0;
                 }
                 if(address != lookup->remote)
                 {
                     return 0;
                 }
                 break;

            case 'C':
                 lookup->country_index = atoi(field + 1);
                 lookup->country_index = lookup->country_index < 0 ? 0 : lookup->country_index;
                 lookup->country_index = lookup->country_index > MAX_COUNTRIES ? 0 : lookup->country_index;
                 strcpy(lookup->country_code2, xgeoip_countries_codes2[lookup->country_index]);
                 strcpy(lookup->country_code3, xgeoip_countries_codes3[lookup->country_index]);
                 strcpy(lookup->country_name, xgeoip_countries_names[lookup->country_index]);
                 strcpy(lookup->continent_code, xgeoip_continents_codes[lookup->country_index]);
                 if(lookup->continent_code[0])
                 {
                     count = 0;
                     while(xgeoip_continents_names[count] &&
                           strcmp(xgeoip_continents_names[count], lookup->continent_code))
                     {
                         count += 2;
                     }
                     if(xgeoip_continents_names[count])
                     {
                         strncpy(lookup->continent_name, xgeoip_continents_names[count + 1], sizeof(lookup->continent_name) - 1);
                     }
                 }
                 break;

            case 'A':
                 strncpy(lookup->region_code, field + 1, sizeof(lookup->region_code) - 1);
                 break;

            case 'R':
                 if(apr_base64_decode_len(field + 1) > (sizeof(lookup->region_name) - 1))
                 {
                     return 0;
                 }
                 apr_base64_decode(lookup->region_name, field + 1);
                 break;

            case 'L':
                 if(apr_base64_decode_len(field + 1) > (sizeof(lookup->city_name) - 1))
                 {
                     return 0;
                 }
                 apr_base64_decode(lookup->city_name, field + 1);
                 break;

            case 'Z':
                 strncpy(lookup->zip_code, field + 1, sizeof(lookup->zip_code) - 1);
                 break;

            case 'X':
                 strncpy(lookup->latitude, field + 1, sizeof(lookup->latitude) - 1);
                 break;

            case 'Y':
                 strncpy(lookup->longitude, field + 1, sizeof(lookup->longitude) - 1);
                 break;

            case 'S':
                 strncpy(lookup->as_number, field + 1, sizeof(lookup->as_number) - 1);
                 break;

            case 'N':
                 if(apr_base64_decode_len(field + 1) > (sizeof(lookup->as_name) - 1))
                 {
                     return 0;
                 }
                 apr_base64_decode(lookup->as_name, field + 1);
                 break;

        }
        field = strtok_r(NULL, ":", &last);
    }
    lookup->found = 1;
    return 1;
}

// Build cookie from lookup structure
static int xgeoip_build_cookie(const xgeoip_configuration *configuration, xgeoip_lookup *lookup, char *output, const long size)
{                                                                                                       
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char          region_name[STRING_SIZE], city_name[STRING_SIZE], as_name[STRING_SIZE];
    int           count, cookie_length;

    if(configuration == NULL || !configuration->enabled || !configuration->initialized || lookup == NULL || output == NULL || size <= 0)
    {
        return 0;
    }
    if(apr_base64_encode_len(strlen(lookup->region_name)) > (sizeof(region_name) - 1))
    {
        return 0;
    }
    if(apr_base64_encode(region_name, lookup->region_name, strlen(lookup->region_name)) < 0)
    {
        return 0;
    }
    if(apr_base64_encode_len(strlen(lookup->city_name)) > (sizeof(city_name) - 1))
    {
        return 0;
    }
    if(apr_base64_encode(city_name, lookup->city_name, strlen(lookup->city_name)) < 0)
    {
        return 0;
    }
    if(apr_base64_encode_len(strlen(lookup->as_name)) > (sizeof(as_name) - 1))
    {
        return 0;
    }
    if(apr_base64_encode(as_name, lookup->as_name, strlen(lookup->as_name)) < 0)
    {
        return 0;
    }
    memset(output, 0 , size);
    if(configuration->cookie_key[0])
    {
        cookie_length = strlen(configuration->cookie_name);
        if(snprintf(output, size - 1,
                    "%s=________________:I%08x:C%d:K%s:A%s:R%s:L%s:Z%s:X%s:Y%s:S%s:N%s%s",
                    configuration->cookie_name,
                    lookup->remote,
                    lookup->country_index,
                    lookup->country_code2,
                    lookup->region_code,
                    region_name,
                    city_name,
                    lookup->zip_code,
                    lookup->latitude,
                    lookup->longitude,
                    lookup->as_number,
                    as_name,
                    configuration->cookie_key) >= (size - 1))
        {
            return 0;
        }
        if(apr_md5(digest, output + cookie_length + 18, strlen(output + cookie_length + 18)))
        {
            return 0;
        }
        for(count = 0; count < 8; count ++)
        {
             output[cookie_length + 1 + (count * 2)]     = ((digest[count] >> 4) <= 9) ? '0' + (digest[count] >> 4): 'a' + (digest[count] >> 4) - 10;
             output[cookie_length + 1 + (count * 2) + 1] = ((digest[count] & 0x0f) <= 9) ? '0' + (digest[count] & 0x0f) : 'a' + (digest[count] & 0x0f) - 10;
        }
        output[strlen(output) - strlen(configuration->cookie_key)] = 0;
    }
    else
    {
        if(snprintf(output, size - 1,
                    "%s=I%08x:C%d:K%s:A%s:R%s:L%s:Z%s:X%s:Y%s:S%s:N%s",
                    configuration->cookie_name,
                    lookup->remote,
                    lookup->country_index,
                    lookup->country_code2,
                    lookup->region_code,
                    region_name,
                    city_name,
                    lookup->zip_code,
                    lookup->latitude,
                    lookup->longitude,
                    lookup->as_number,
                    as_name) >= (size - 1))
        {
            return 0;
        }
    }
    if(configuration->cookie_domain[0])
    {
        cookie_length = strlen(output);
        if(snprintf(output + cookie_length, sizeof(output) - cookie_length - 1, "; path=/; domain=%s",
                    configuration->cookie_domain) >= (sizeof(output) - cookie_length - 1))
        {
            return 0;
        }
    }
    return 1;
}

// Retrieve geoip information
static int xgeoip_post_read_request(request_rec *request)
{
    xgeoip_configuration *configuration;
    xgeoip_lookup        lookup;
    char                 content[STRING_SIZE];
    int                  count;

    configuration = ap_get_module_config(request->server->module_config, &xgeoip_module);
    if(! configuration)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, request->server, "XGeoIP Invalid configuration record - request ignored");
        return OK;
    }
    if(!configuration->enabled || !configuration->initialized)
    {
        return OK;
    }
    if(! xgeoip_lookup_init(request, configuration, &lookup, NULL))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, request->server, "XGeoIP Cannot initialize lookup record - request ignored");
        return OK;
    }
    if(configuration->cookie_enabled)
    {
        xgeoip_lookup_from_cookie(configuration, apr_table_get(request->headers_in, "Cookie"), &lookup);
    }
    if(! lookup.found)
    {
        for(count = 0; count < configuration->database_count; count ++)
        {
             xgeoip_lookup_from_database(configuration, count, &lookup);
        }
    }
    if(configuration->cookie_enabled)
    {
        if(xgeoip_build_cookie(configuration, &lookup, content, sizeof(content)))
        {
            apr_table_add(request->headers_out, "Set-Cookie", content);
        }
    }
    sprintf(content, "%d.%d.%d.%d", lookup.remote & 0xff, (lookup.remote >> 8) & 0xff, (lookup.remote >> 16) & 0xff, lookup.remote >> 24);
    sprintf(content + 20, "%d.%d.%d.%d", lookup.proxy & 0xff, (lookup.proxy >> 8) & 0xff, (lookup.proxy >> 16) & 0xff, lookup.proxy >> 24);
    if(configuration->mode & MODE_NOTE)
    {
        apr_table_set(request->notes, "XGEOIP_MODULE_VERSION", MODULE_VERSION);
        apr_table_set(request->notes, "XGEOIP_DATABASE_DATE",  configuration->database_date[0]);
        apr_table_set(request->notes, "XGEOIP_REMOTE_IP",      content);
        apr_table_set(request->notes, "XGEOIP_PROXY_IP",       content + 20);
        apr_table_set(request->notes, "XGEOIP_COUNTRY_CODE2",  lookup.country_code2);
        apr_table_set(request->notes, "XGEOIP_COUNTRY_CODE3",  lookup.country_code3);
        apr_table_set(request->notes, "XGEOIP_COUNTRY_NAME",   lookup.country_name);
        apr_table_set(request->notes, "XGEOIP_CONTINENT_CODE", lookup.continent_code);
        apr_table_set(request->notes, "XGEOIP_CONTINENT_NAME", lookup.continent_name);
        apr_table_set(request->notes, "XGEOIP_REGION_CODE",    lookup.region_code);
        apr_table_set(request->notes, "XGEOIP_REGION_NAME",    lookup.region_name);
        apr_table_set(request->notes, "XGEOIP_CITY_NAME",      lookup.city_name);
        apr_table_set(request->notes, "XGEOIP_ZIP_CODE",       lookup.zip_code);
        apr_table_set(request->notes, "XGEOIP_LATITUDE",       lookup.latitude);
        apr_table_set(request->notes, "XGEOIP_LONGITUDE",      lookup.longitude);
        apr_table_set(request->notes, "XGEOIP_AS_NUMBER",      lookup.as_number);
        apr_table_set(request->notes, "XGEOIP_AS_NAME",        lookup.as_name);
    }
    if(configuration->mode & MODE_ENV)
    {
        apr_table_set(request->subprocess_env, "XGEOIP_MODULE_VERSION", MODULE_VERSION);
        apr_table_set(request->subprocess_env, "XGEOIP_DATABASE_DATE",  configuration->database_date[0]);
        apr_table_set(request->subprocess_env, "XGEOIP_REMOTE_IP",      content);
        apr_table_set(request->subprocess_env, "XGEOIP_PROXY_IP",       content + 20);
        apr_table_set(request->subprocess_env, "XGEOIP_COUNTRY_CODE2",  lookup.country_code2);
        apr_table_set(request->subprocess_env, "XGEOIP_COUNTRY_CODE3",  lookup.country_code3);
        apr_table_set(request->subprocess_env, "XGEOIP_COUNTRY_NAME",   lookup.country_name);
        apr_table_set(request->subprocess_env, "XGEOIP_CONTINENT_CODE", lookup.continent_code);
        apr_table_set(request->subprocess_env, "XGEOIP_CONTINENT_NAME", lookup.continent_name);
        apr_table_set(request->subprocess_env, "XGEOIP_REGION_CODE",    lookup.region_code);
        apr_table_set(request->subprocess_env, "XGEOIP_REGION_NAME",    lookup.region_name);
        apr_table_set(request->subprocess_env, "XGEOIP_CITY_NAME",      lookup.city_name);
        apr_table_set(request->subprocess_env, "XGEOIP_ZIP_CODE",       lookup.zip_code);
        apr_table_set(request->subprocess_env, "XGEOIP_LATITUDE",       lookup.latitude);
        apr_table_set(request->subprocess_env, "XGEOIP_LONGITUDE",      lookup.longitude);
        apr_table_set(request->subprocess_env, "XGEOIP_AS_NUMBER",      lookup.as_number);
        apr_table_set(request->subprocess_env, "XGEOIP_AS_NAME",        lookup.as_name);
    }
    return OK;
}

// Request handler (return geoip information directly to client)
static int xgeoip_handler(request_rec *request)
{
    xgeoip_configuration *configuration;
    xgeoip_lookup        lookup;
    char                 content[STRING_SIZE], *remote = NULL, *last;
    int                  count;

    if(request->method_number != M_GET || strcmp(request->handler, "xgeoip")) 
    {
        return DECLINED;
    }
    configuration = ap_get_module_config(request->server->module_config, &xgeoip_module);
    if(! configuration || ! configuration->enabled || ! configuration->initialized)
    {
        return DECLINED;
    }
    memset(content, 0, sizeof(content));
    if(request->args)
    {
        strncpy(content, request->args, sizeof(content) - 1);
        remote = strtok_r(content, "&", &last);
        while(remote)
        {
            if(! strncasecmp(remote, "remote=", 7))
            {
                remote += 7;
                break;
            }
            remote = strtok_r(NULL, "&", &last);
        }
    }
    if(! xgeoip_lookup_init(request, configuration, &lookup, remote))
    {
        return DECLINED;
    }
    for(count = 0; count < configuration->database_count; count ++)
    {
         xgeoip_lookup_from_database(configuration, count, &lookup);
    }
    sprintf(content, "%d.%d.%d.%d", lookup.remote & 0xff, (lookup.remote >> 8) & 0xff, (lookup.remote >> 16) & 0xff, lookup.remote >> 24);
    sprintf(content + 20, "%d.%d.%d.%d", lookup.proxy & 0xff, (lookup.proxy >> 8) & 0xff, (lookup.proxy >> 16) & 0xff, lookup.proxy >> 24);
    if(strstr(request->uri, ".xml"))
    {
        request->content_type = "text/xml";
        ap_rprintf(request, "<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>"
                            "<xgeoip module_version=\"%s\" database_date=\"%s\">"
                            "<remote_ip>%s</remote_ip>"
                            "<proxy_ip>%s</proxy_ip>"
                            "<country_code2>%s</country_code2>"
                            "<country_code3>%s</country_code3>"
                            "<country_name>%s</country_name>"
                            "<continent_code>%s</continent_code>"
                            "<continent_name>%s</continent_name>"
                            "<region_code>%s</region_code>"
                            "<region_name>%s</region_name>"
                            "<city_name>%s</city_name>"
                            "<zip_code>%s</zip_code>"
                            "<latitude>%s</latitude>"
                            "<longitude>%s</longitude>"
                            "<as_number>%s</as_number>"
                            "<as_name>%s</as_name>"
                            "</xgeoip>",
                   MODULE_VERSION,
                   configuration->database_date[0],
                   content,
                   content + 20,
                   lookup.country_code2,
                   lookup.country_code3,
                   lookup.country_name,
                   lookup.continent_code,
                   lookup.continent_name,
                   lookup.region_code,
                   lookup.region_name,
                   lookup.city_name,
                   lookup.zip_code,
                   lookup.latitude,
                   lookup.longitude,
                   lookup.as_number,
                   lookup.as_name);
    }
    else if(strstr(request->uri, ".json"))
    {
        request->content_type = "application/json";
        ap_rprintf(request, "{\"module_version\": \"%s\", "
                            "\"database_date\": \"%s\", "
                            "\"remote_ip\": \"%s\", "
                            "\"proxy_ip\": \"%s\", "
                            "\"country_code2\": \"%s\", "
                            "\"country_code3\": \"%s\", "
                            "\"country_name\": \"%s\", "
                            "\"continent_code\": \"%s\", "
                            "\"continent_name\": \"%s\", "
                            "\"region_code\": \"%s\", "
                            "\"region_name\": \"%s\", "
                            "\"city_name\": \"%s\", "
                            "\"zip_code\": \"%s\", "
                            "\"latitude\": \"%s\", "
                            "\"longitude\": \"%s\", "
                            "\"as_number\": \"%s\", "
                            "\"as_name\": \"%s\"}",
                   MODULE_VERSION,
                   configuration->database_date[0],
                   content,
                   content + 20,
                   lookup.country_code2,
                   lookup.country_code3,
                   lookup.country_name,
                   lookup.continent_code,
                   lookup.continent_name,
                   lookup.region_code,
                   lookup.region_name,
                   lookup.city_name,
                   lookup.zip_code,
                   lookup.latitude,
                   lookup.longitude,
                   lookup.as_number,
                   lookup.as_name);
    }
    else
    {
        request->content_type = "text/plain";
        ap_rprintf(request, "module_version %s\n"
                            "database_date %s\n"
                            "remote_ip %s\n"
                            "proxy_ip %s\n"
                            "country_code2 %s\n"
                            "country_code3 %s\n"
                            "country_name %s\n"
                            "continent_code %s\n"
                            "continent_name %s\n"
                            "region_code %s\n"
                            "region_name %s\n"
                            "city_name %s\n"
                            "zip_code %s\n"
                            "latitude %s\n"
                            "longitude %s\n"
                            "as_number %s\n"
                            "as_name %s\n",
                   MODULE_VERSION,
                   configuration->database_date[0],
                   content,
                   content + 20,
                   lookup.country_code2,
                   lookup.country_code3,
                   lookup.country_name,
                   lookup.continent_code,
                   lookup.continent_name,
                   lookup.region_code,
                   lookup.region_name,
                   lookup.city_name,
                   lookup.zip_code,
                   lookup.latitude,
                   lookup.longitude,
                   lookup.as_number,
                   lookup.as_name);
    }
    return OK;
}

// Hooks registering
static void xgeoip_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(xgeoip_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(xgeoip_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(xgeoip_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

// Module v-table
module AP_MODULE_DECLARE_DATA xgeoip_module = 
{
    STANDARD20_MODULE_STUFF, 
    NULL,
    NULL,
    xgeoip_create_configuration,
    NULL,
    xgeoip_cmds,
    xgeoip_register_hooks
};
