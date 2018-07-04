/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License. For a copy,
 * see http://www.gnu.org/licenses/gpl-2.0.html.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include "config.h"

#if defined(ENABLE_XSLT) || defined(ENABLE_MONITOR)

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifdef ENABLE_XSLT
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>
#endif
#include "libstr.h"
#include "http.h"
#include "send.h"
#include "log.h"
#include "tomahawk.h"
#include "memdbg.h"

#define XSLT_INDEX "/index.xslt\0"
#define XSLT_INDEX_LEN   12
#define VALUE_SIZE       16
#define LINE_SIZE      1024
#define MAX_PARAMETERS  200 /* must be even */
#define MAX_NAME_LEN    100
#define MAX_HEADER_LEN  100
#define XML_CHUNK_LEN  2048

extern char *hs_conlen;
extern char *fb_filesystem;
extern char *fb_symlink;
extern char *unknown_http_code;

/* Translate spacial characters
 */
static int xml_special_chars(char *str, char **new) {
	size_t len;
	char *c;

	if (str == NULL) {
		*new = NULL;
		return -1;
	}
	len = strlen(str);

	if ((*new = (char*)malloc(len * 6 + 1)) == NULL) {
		return -1;
	}
	c = *new;

	while (*str != '\0') {
		if (*str == '&') {
			strcpy(c, "&amp;");
			c += 5;
		} else if (*str == '\"') {
			strcpy(c, "&quot;");
			c += 6;
		} else if (*str == '\'') {
			strcpy(c, "&apos;");
			c += 6;
		} else if (*str == '<') {
			strcpy(c, "&lt;");
			c += 4;
		} else if (*str == '>') {
			strcpy(c, "&gt;");
			c += 4;
		} else {
			*c = *str;
			c++;
		}

		str++;
	}
	*c = '\0';

	return 0;
}

#ifdef ENABLE_XSLT

/* XSLT transform parameter functions
 */
static void add_parameter(const char **params, char *key, char *value, int *i) {
	size_t key_len;
	char *str;

	if (key == NULL) {
		return;
	} else if (value == NULL) {
		value = "";
	}

	if (*i + 2 > MAX_PARAMETERS) {
		return;
	}

	key_len = strlen(key);
	if ((str = (char*)malloc(key_len + strlen(value) + 4)) == NULL) {
		return;
	}

	if (forbidden_chars_present(value)) {
		free(str);
		return;
	} else if ((value = strdup(value)) == NULL) {
		free(str);
		return;
	}
	url_decode(value);

	if (strchr(value, '\'') == NULL) {
		sprintf(str, "%s%c'%s'", key, 0, value);
	} else if (strchr(value, '"') == NULL) {
		sprintf(str, "%s%c\"%s\"", key, 0, value);
	} else {
		free(value);
		free(str);
		return;
	}
	free(value);

	params[(*i)++] = str;
	params[(*i)++] = str + key_len + 1;
}

static void add_http_header(t_session *session, const char **params, char *header, char *key, int *i) {
	char *value;

	value = get_http_header(header, session->http_headers);
	add_parameter(params, key, value, i);
}

static void add_parameter_line(const char **params, char *line, char split, char *prefix, int *i) {
	char *item, *key, *value, name[MAX_NAME_LEN + 1];
	size_t prefix_len, key_len;

	prefix_len = strlen(prefix);
	while (line != NULL) {
		split_string(line, &item, &line, split);
		if (split_string(item, &key, &value, '=') == -1) {
			continue;
		}

		key_len = strlen(key);
		if (prefix_len + key_len > MAX_NAME_LEN) {
			continue;
		}

		memcpy(name, prefix, prefix_len);
		strncpy(name + prefix_len, key, key_len + 1);

		add_parameter(params, name, value, i);
	}
}

static const char **get_transform_parameters(t_session *session) {
	char ip[MAX_IP_STR_LEN], value[20], variable[MAX_HEADER_LEN];
	t_http_header *http_headers;
	const char **params;
	int i = 0;

	if ((params = (const char**)malloc(sizeof(void*) * (MAX_PARAMETERS + 1))) == NULL) {
		return NULL;
	}

	add_parameter(params, "REQUEST_METHOD", session->method, &i);
	add_parameter(params, "REQUEST_URI", session->request_uri, &i);
	add_parameter(params, "SERVER_PROTOCOL", session->http_version, &i);
	if (inet_ntop(session->ip_address.family, &(session->ip_address.value), ip, MAX_IP_STR_LEN) != NULL) {
		add_parameter(params, "REMOTE_ADDR", ip, &i);
	}

	value[19] = '\0';
	snprintf(value, 9, "%d", session->binding->port);
	add_parameter(params, "SERVER_PORT", value, &i);
	add_parameter(params, "SERVER_NAME", *(session->host->hostname.item), &i);
	if (session->config->server_string != NULL) {
		add_parameter(params, "SERVER_SOFTWARE", session->config->server_string, &i);
	}
#ifdef ENABLE_TLS
	if (session->binding->use_tls) {
		add_parameter(params, "HTTP_SCHEME", "https", &i);
	} else
#endif
		add_parameter(params, "HTTP_SCHEME", "http", &i);

	if (session->http_auth == basic) {
		add_parameter(params, "AUTH_TYPE", "Basic", &i);
	} else if (session->http_auth == digest) {
		add_parameter(params, "AUTH_TYPE", "Digest", &i);
	}
	add_parameter(params, "REMOTE_USER", session->remote_user, &i);

	add_http_header(session, params, "Accept:", "HTTP_ACCEPT", &i);
	add_http_header(session, params, "Accept-Charset:", "HTTP_ACCEPT_CHARSET", &i);
	add_http_header(session, params, "Accept-Encoding:", "HTTP_ACCEPT_ENCODING", &i);
	add_http_header(session, params, "Accept-Language:", "HTTP_ACCEPT_LANGUAGE", &i);
	add_http_header(session, params, "Client-IP:", "HTTP_CLIENT_IP", &i);
	add_http_header(session, params, "From:", "HTTP_FROM", &i);
	add_http_header(session, params, "Host:", "HTTP_HOST", &i);
	add_http_header(session, params, "If-Modified-Since:", "HTTP_IF_MODIFIED_SINCE", &i);
	add_http_header(session, params, "If-Unmodified-Since:", "HTTP_IF_UNMODIFIED_SINCE", &i);
	add_http_header(session, params, "Origin:", "HTTP_ORIGIN", &i);
	add_http_header(session, params, "Range:", "HTTP_RANGE", &i);
	add_http_header(session, params, "Referer:", "HTTP_REFERER", &i);
	add_http_header(session, params, "User-Agent:", "HTTP_USER_AGENT", &i);
	add_http_header(session, params, "Via:", "HTTP_VIA", &i);

	/* Convert X-* HTTP headers to HTTP_* variables
	 */
	http_headers = session->http_headers;
	while (http_headers != NULL) {
		if (strncmp(http_headers->data, "X-", 2) == 0) {
			if (header_to_variable(http_headers->data, (char*)&variable, MAX_HEADER_LEN) != -1) {
				add_parameter(params, variable, http_headers->data + http_headers->value_offset, &i);
			}
		}
		http_headers = http_headers->next;
	}

	value[19] = '\0';
	snprintf(value, 19, "%d", session->return_code);
	add_parameter(params, "HTTP_RETURN_CODE", value, &i);
	if (session->error_code != -1) {
		snprintf(value, 9, "%d", session->error_code);
		add_parameter(params, "HTTP_GENERATED_ERROR", value, &i);
	}

	add_parameter(params, "QUERY_STRING", session->vars, &i);
	if (session->body != NULL) {
		value[19] = '\0';
		snprintf(value, 19, "%ld", session->content_length);
		add_parameter(params, "CONTENT_LENGTH", value, &i);
		add_http_header(session, params, "Content-Type:", "CONTENT_TYPE", &i);
	}

	add_parameter_line(params, session->vars, '&', "GET_", &i);
	add_parameter_line(params, session->body, '&', "POST_", &i);
	add_parameter_line(params, session->cookies, ';', "COOKIE_", &i);

	params[i] = NULL;

	return params;
}

static void dispose_transform_parameters(const char **params) {
	char **param;

	if (params == NULL) {
		return;
	}

	param = (char**)params;
	while (*param != NULL) {
		free(*param);
		param += 2;
	}

	free(params);
}

/* XSLT transform functions
 */
void init_xslt_module() {
	xmlInitMemory();
	xmlInitParser();
}

char *find_xslt_file(t_session *session) {
	char *xslt, *slash;
	size_t len;
	FILE *fp;

	/* Check virtual host settings
	 */
	if (session->host->use_xslt == false) {
		return NULL;
	}

	/* Check extension
	 */
	if (session->extension == NULL) {
		return NULL;
	} else if (strcmp(session->extension, "xml") != 0) {
		return NULL;
	}

	/* Check for XSLT existence: <file>.xslt
	 */
	if ((len = strlen(session->file_on_disk)) < 4) {
		return NULL;
	} else if ((xslt = (char*)malloc(len + 2)) == NULL) {
		return NULL;
	}
	memcpy(xslt, session->file_on_disk, len - 3);
	memcpy(xslt + len - 3, "xslt\0", 5);
	if ((fp = fopen(xslt, "r")) != NULL) {
		fclose(fp);
		return xslt;
	}
	free(xslt);

	/* Check for XSLT existence: index.xslt in directory
	 */
	if ((slash = strrchr(session->file_on_disk, '/')) == NULL) {
		return NULL;
	}
	len = slash - session->file_on_disk;
	if ((xslt = (char*)malloc(len + XSLT_INDEX_LEN)) == NULL) {
		return NULL;
	}
	memcpy(xslt, session->file_on_disk, len);
	memcpy(xslt + len, XSLT_INDEX, XSLT_INDEX_LEN);
	if ((fp = fopen(xslt, "r")) != NULL) {
		fclose(fp);
		return xslt;
	}
	free(xslt);

	/* Check for XSLT existence: /index.xslt
	 */
	if ((xslt = (char*)malloc(session->host->website_root_len + XSLT_INDEX_LEN)) == NULL) {
		return NULL;
	}
	memcpy(xslt, session->host->website_root, session->host->website_root_len);
	memcpy(xslt + session->host->website_root_len, XSLT_INDEX, XSLT_INDEX_LEN);
	if ((fp = fopen(xslt, "r")) != NULL) {
		fclose(fp);
		return xslt;
	}
	free(xslt);

	return NULL;
}

/* Apply XSLT sheet
 */
static int apply_xslt_sheet(t_session *session, xmlDocPtr data_xml, char *xslt_file) {
	xmlDocPtr style_xml, result_xml;
	xsltStylesheetPtr xslt;
	xmlChar *raw_xml;
	FILE *fp;
	char value[VALUE_SIZE + 1];
	const char **params;
	int result = 200, raw_size;

	/* Read XML data
	 */
	if (data_xml == NULL) {
		log_error_file(session, session->file_on_disk, "data is invalid XML");
		return 500;
	}

	/* Read XSLT sheet
	 */
	if (xslt_file == NULL) {
		log_error_file(session, xslt_file, "XSLT file not set");
		return 500;
	}

	if ((fp = fopen(xslt_file, "r")) == NULL) {
		log_error_file(session, xslt_file, "XSLT file does not exist");
		return 500;
	}
	fclose(fp);

	if ((style_xml = xmlReadFile(xslt_file, NULL, 0)) == NULL) {
		log_error_file(session, xslt_file, "XSLT file contains invalid XML");
		return 500;
	}

	if ((xslt = xsltParseStylesheetDoc(style_xml)) == NULL) {
		log_error_file(session, xslt_file, "invalid XSLT");
		xmlFreeDoc(style_xml);
		return 500;
	}

	/* Mimetype
	 */
	session->mimetype = get_mimetype(session->extension, session->config->mimetype);
	if (xslt->method != NULL) {
		if (strcmp((char*)xslt->method, "html") == 0) {
			session->mimetype = get_mimetype("html", session->config->mimetype);
		}
	}

	/* Transform XML to HTML
	 */
	params = get_transform_parameters(session);
	result_xml = xsltApplyStylesheet(xslt, data_xml, params);
	dispose_transform_parameters(params);

	/* Handle transformation result
	 */
	if (result_xml == NULL) {
		log_error_file(session, session->file_on_disk, "transformation error");
		xmlFreeDoc(result_xml);
		xsltFreeStylesheet(xslt);
		return 500;
	}
	if (xsltSaveResultToString(&raw_xml, &raw_size, result_xml, xslt) == -1) {
		log_error_file(session, session->file_on_disk, "transformation error");
		xmlFreeDoc(result_xml);
		xsltFreeStylesheet(xslt);
		return 500;
	}

	/* Print HTML
	 */
	value[VALUE_SIZE] = '\0';
	if (send_buffer(session, hs_conlen, 16) == -1) {
		result = -1;
	} else if (snprintf(value, VALUE_SIZE, "%d\r\n\r\n", raw_size) == -1) {
		result = -1;
	} else if (send_buffer(session, value, strlen(value)) == -1) {
		result = -1;
	} else if (send_buffer(session, (char*)raw_xml, raw_size) == -1) {
		result = -1;
	}

	/* Free buffers
	 */
	xmlFree(raw_xml);
	xmlFreeDoc(result_xml);
	xsltFreeStylesheet(xslt);

	return result;
}

/* Apply XSLT to XML file
 */
int transform_xml(t_session *session, char *xslt_file) {
	xmlDocPtr data_xml;
	int result;

	if (send_header(session) == -1) {
		return -1;
	}

	data_xml = xmlReadFile(session->file_on_disk, NULL, 0);
	result = apply_xslt_sheet(session, data_xml, xslt_file);
	xmlFreeDoc(data_xml);

	return result;
}

#endif

/* Add XML tag to buffer
 */
static int add_tag(char **buffer, int *size, int extra_size, int *len, char *tag, char *str) {
	int result;
	char data[32];

	if (str == NULL) {
		return 0;
	}

	if ((result = snprintf(data, 31, "<%s>", tag)) == -1) {
		return -1;
	} else if (result >= 30) {
		return false;
	}
	if (add_str(buffer, size, extra_size, len, data) == -1) {
		return -1;
	}

	if (add_str(buffer, size, extra_size, len, str) == -1) {
		return -1;
	}

	if ((result = snprintf(data, 31, "</%s>", tag)) == -1) {
		return -1;
	} else if (result >= 30) {
		return false;
	}
	if (add_str(buffer, size, extra_size, len, data) == -1) {
		return -1;
	}

	return 0;
}

/* Apply XSLT to directory index
 */
int show_index(t_session *session) {
#ifdef ENABLE_XSLT
	xmlDocPtr data_xml;
#endif
	char *text_xml, fsize_str[30], timestr[33], value[VALUE_SIZE + 1], *extension, *ext_xml, *link, *slash, *uri, *ruri;
	int text_size, text_max, result, handle;
	off_t total_fsize = 0;
	bool root_dir, show_xml;
	struct tm s;
	t_filelist *filelist = NULL, *file;
	t_keyvalue *alias;

#ifdef ENABLE_DEBUG
	session->current_task = "show index";
#endif

#ifdef ENABLE_TOMAHAWK
	increment_counter(COUNTER_INDEX);
#endif

	session->mimetype = NULL;

	if ((slash = strrchr(session->file_on_disk, '/')) == NULL) {
		return 500;
	}
	*(slash + 1) = '\0';

	switch (file_type(session->file_on_disk)) {
		case ft_error:
			return 500;
		case ft_other:
			return 403;
		case ft_file:
		case ft_not_found:
			return 404;
		case ft_no_access:
			log_error_session(session, fb_filesystem);
			return 403;
			break;
		case ft_dir:
			break;
	}

	if (session->host->follow_symlinks == false) {
		switch (contains_not_allowed_symlink(session->file_on_disk, session->host->website_root)) {
			case fb_error:
				log_error_session(session, "error while scanning file for symlinks");
				return 500;
			case fb_not_found:
				return 404;
			case fb_no_access:
			case fb_yes:
				log_error_session(session, fb_symlink);
				return 403;
			case fb_no:
				break;
		}
	}

	session->mimetype = "text/html";

	/* HTTP/1.0 has no knowledge about chunked Transfer-Encoding.
	 */
	if (*(session->http_version + 7) == '0') {
		session->keep_alive = false;
	}

	if (send_header(session) == -1) {
		return -1;
	}

	if (session->request_method == HEAD) {
		if (send_buffer(session, "\r\n", 2) == -1) {
			return -1;
		}
		return 200;
	}

	/* Read directory content
	 */
	if ((filelist = read_filelist(session->file_on_disk, session->host->allow_dot_files)) == NULL) {
		return 500;
	}

	/* Add aliasses to directory list
	 */
	if (strcmp(session->uri, "/") == 0) {
		alias = session->host->alias;
		while (alias != NULL) {
			if ((file = (t_filelist*)malloc(sizeof(t_filelist))) == NULL) {
				remove_filelist(filelist);
				return 500;
			} else if ((file->name = strdup(alias->key + 1)) == NULL) {
				free(file);
				remove_filelist(filelist);
				return 500;
			}
			file->size = 0;
			file->time = session->time;
			file->is_dir = true;
			file->next = filelist;
			filelist = file;

			alias = alias->next;
		}
	}

	file = filelist = sort_filelist(filelist);

	root_dir = (strcmp(session->uri, "/") == 0);

	text_max = XML_CHUNK_LEN;
	if ((text_xml = (char*)malloc(text_max)) == NULL) {
		remove_filelist(filelist);
		return -1;
	}
	text_size = 0;

	/* Start XML
	 */
	if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<index>") == -1) {
		free(text_xml);
		remove_filelist(filelist);
		return -1;
	}

	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "hostname", *(session->host->hostname.item)) == -1) {
		free(text_xml);
		remove_filelist(filelist);
		return -1;
	}

	if ((uri = strdup(session->request_uri)) == NULL) {
		free(text_xml);
		remove_filelist(filelist);
		return -1;
	}
	url_decode(uri);
	if (xml_special_chars(uri, &ruri) == -1) {
		free(uri);
		free(text_xml);
		remove_filelist(filelist);
		return -1;
	}
	free(uri);
	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "request_uri", ruri) == -1) {
		free(text_xml);
		free(ruri);
		remove_filelist(filelist);
		return -1;
	}
	free(ruri);

	if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "<files>") == -1) {
		free(text_xml);
		remove_filelist(filelist);
		return -1;
	}

	/* Loop through files
	 */
	while (file != NULL) {
		if (file->is_dir && root_dir) {
			if (strcmp(file->name, "..") == 0) {
				file = file->next;
				continue;
			}
		}

		if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "<file type=\"") == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, (file->is_dir ? "dir" : "file")) == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		}

		/* Timestamp
		 */
		localtime_r(&(file->time), &s);
		strftime(timestr, 32, "%d %b %Y, %X", &s);
		*(timestr + 32) = '\0';

		if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "\" timestamp=\"") == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, timestr) == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		}

		if (file->is_dir == false) {
			/* File size
		 	 */
			if (filesize2str(fsize_str, 30, file->size) == -1) {
				free(text_xml);
				remove_filelist(filelist);
				return -1;
			} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "\" size=\"") == -1) {
				free(text_xml);
				remove_filelist(filelist);
				return -1;
			} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, fsize_str) == -1) {
				free(text_xml);
				remove_filelist(filelist);
				return -1;
			}

			/* Extension
			 */
			if ((extension = strrchr(file->name, '.')) != NULL) {
				ext_xml = NULL;
				if (xml_special_chars(extension + 1, &ext_xml) == -1) {
					free(text_xml);
					remove_filelist(filelist);
					return -1;
				} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "\" extension=\"") == -1) {
					free(text_xml);
					check_free(ext_xml);
					remove_filelist(filelist);
					return -1;
				} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, ext_xml) == -1) {
					free(text_xml);
					check_free(ext_xml);
					remove_filelist(filelist);
					return -1;
				}
				check_free(ext_xml);
			}
		}

		/* URL encoded
		 */
		link = NULL;
		if (url_encode(file->name, &link) == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "\" url_encoded=\"") == -1) {
			free(text_xml);
			check_free(link);
			remove_filelist(filelist);
			return -1;
		} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, link == NULL ? file->name : link) == -1) {
			free(text_xml);
			check_free(link);
			remove_filelist(filelist);
			return -1;
		} else if (file->is_dir) {
			if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "/") == -1) {
				free(text_xml);
				check_free(link);
				remove_filelist(filelist);
				return -1;
			}
		}
		check_free(link);

		if (xml_special_chars(file->name, &link) == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "\">") == -1) {
			free(text_xml);
			check_free(link);
			remove_filelist(filelist);
			return -1;
		} else if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, link == NULL ? file->name : link) == -1) {
			free(text_xml);
			check_free(link);
			remove_filelist(filelist);
			return -1;
		} else {
			check_free(link);
		}

		if (file->is_dir) {
			if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "/") == -1) {
				free(text_xml);
				remove_filelist(filelist);
				return -1;
			}
		}

		if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "</file>") == -1) {
			free(text_xml);
			remove_filelist(filelist);
			return -1;
		}

		if (file->is_dir == false) {
			total_fsize += file->size;
		}

		file = file->next;
	}

	remove_filelist(filelist);

	if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "</files>") == -1) {
		free(text_xml);
		return -1;
	}

	if (session->remote_user != NULL) {
		if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "remote_user", session->remote_user) == -1) {
			free(text_xml);
			return -1;
		}
	}

	/* Total size
	 */
	if (filesize2str(fsize_str, 30, total_fsize) == -1) {
		free(text_xml);
		return -1;
	} else if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "total_size", fsize_str) == -1) {
		free(text_xml);
		return -1;
	}

	if (session->config->server_string != NULL) {
		if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "software", session->config->server_string) == -1) {
			free(text_xml);
			return -1;
		}
	}

	if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "</index>") == -1) {
		free(text_xml);
		return -1;
	}

	if (strcmp(session->host->show_index, "xml") == 0) {
		show_xml = true;
	} else if ((handle = open(session->host->show_index, O_RDONLY)) == -1) {
		if (errno == EACCES) {
			log_error_file(session, session->host->show_index, "access denied");
		} else {
			log_error_file(session, session->host->show_index, "file not found");
		}

		show_xml = true;
	} else {
		show_xml = false;
	}

	/* Show listing
	 */
	if (show_xml) {
		value[VALUE_SIZE] = '\0';
		if (send_buffer(session, "Content-Type: text/xml\r\n", 24) == 1) {
			result = -1;
		} else if (send_buffer(session, hs_conlen, 16) == -1) {
			result = -1;
		} else if (snprintf(value, VALUE_SIZE, "%ld\r\n\r\n", (long)strlen(text_xml)) == -1) {
			result = -1;
		} else if (send_buffer(session, value, strlen(value)) == -1) {
			result = -1;
		} else if (send_buffer(session, text_xml, text_size) == -1) {
			result = -1;
		} else {
			result = 200;
		}

		free(text_xml);

		return result;
	}

	close(handle);

#ifdef ENABLE_XSLT
	data_xml = xmlReadMemory(text_xml, text_size, "index.xml", NULL, 0);
	result = apply_xslt_sheet(session, data_xml, session->host->show_index);

	xmlFreeDoc(data_xml);
	free(text_xml);

	return result;
#else
	return -1;
#endif
}

#endif

#ifdef ENABLE_XSLT

/* Show body of HTTP error message
 */
int show_http_code_body(t_session *session) {
	xmlDocPtr data_xml;
	char *text_xml;
	int text_size, text_max, result;
	char ecode[5], *emesg, *uri;

	ecode[4] = '\0';
	snprintf(ecode, 4, "%d", session->return_code);

	if ((emesg = (char*)http_error(session->return_code)) == NULL) {
		emesg = unknown_http_code;
	}

	text_max = XML_CHUNK_LEN;
	if ((text_xml = (char*)malloc(text_max)) == NULL) {
		return -1;
	}
	text_size = 0;

	/* Start XML
	 */
	if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<error>") == -1) {
		free(text_xml);
		return -1;
	}

	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "code", ecode) == -1) {
		free(text_xml);
		return -1;
	}

	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "message", emesg) == -1) {
		free(text_xml);
		return -1;
	}

	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "hostname", *(session->host->hostname.item)) == -1) {
		free(text_xml);
		return -1;
	}

	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "request_method", session->method) == -1) {
		free(text_xml);
		return -1;
	}

	if (xml_special_chars(session->request_uri, &uri) == -1) {
		free(text_xml);
		return -1;
	}
	if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "request_uri", uri) == -1) {
		free(uri);
		free(text_xml);
		return -1;
	}
	free(uri);

	if (session->config->server_string != NULL) {
		if (add_tag(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "software", session->config->server_string) == -1) {
			free(text_xml);
			return -1;
		}
	}

	if (add_str(&text_xml, &text_max, XML_CHUNK_LEN, &text_size, "</error>") == -1) {
		free(text_xml);
		return -1;
	}

	data_xml = xmlReadMemory(text_xml, text_size, "index.xml", NULL, 0);
	result = apply_xslt_sheet(session, data_xml, session->host->error_xslt_file);

	xmlFreeDoc(data_xml);
	free(text_xml);

	return result;
}

#endif
