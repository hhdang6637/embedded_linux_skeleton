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

#ifdef ENABLE_TOOLKIT

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "toolkit.h"
#include "libstr.h"
#include "libfs.h"
#include "alternative.h"
#include "memdbg.h"

#define REGEXEC_NMATCH 10
#define MAX_SUB_DEPTH  10
#define MAX_MATCH_LOOP 20

t_url_toolkit *select_toolkit(char *toolkit_id, t_url_toolkit *url_toolkit) {
	if (toolkit_id == NULL) {
		return NULL;
	}

	while (url_toolkit != NULL) {
		if (strcmp(url_toolkit->toolkit_id, toolkit_id) == 0) {
			return url_toolkit;
		}
		url_toolkit = url_toolkit->next;
	}

	return NULL;
}

static int replace(char *src, int ofs, int len, char *rep, char **dst) {
	size_t len_rep;

	if ((src == NULL) || (rep == NULL) || (dst == NULL)) {
		return -1;
	}

	len_rep = strlen(rep);
	if ((*dst = (char*)malloc(strlen(src) - len + len_rep + 1)) == NULL) {
		return -1;
	}

	memcpy(*dst, src, ofs);
	memcpy(*dst + ofs, rep, len_rep);
	strcpy(*dst + ofs + len_rep, src + ofs + len);

	return 0;
}

t_url_toolkit *new_url_toolkit(void) {
	t_url_toolkit *url_toolkit;

	if ((url_toolkit = (t_url_toolkit*)malloc(sizeof(t_url_toolkit))) == NULL) {
		return NULL;
	}

	url_toolkit->toolkit_id = NULL;
	url_toolkit->toolkit_rule = NULL;
	url_toolkit->next = NULL;

	return url_toolkit;
}

static bool parse_parameters(t_toolkit_rule *new_rule, char *value, char **operation) {
	char *rest;
	bool allowed = false;
	int loop;

	split_string(value, &value, &rest, ' ');

	while (*operation != NULL) {
		if (strcasecmp(*operation, value) == 0) {
			allowed = true;
			break;
		}
		operation++;
	}

	if (allowed == false) {
		return false;
	}

	if (strcasecmp(value, "ban") == 0) {
		/* Ban
		 */
		new_rule->operation = to_ban;

		if ((new_rule->value = time_str_to_int(rest)) == -1) {
			return false;
		}
	} else if (strcasecmp(value, "call") == 0) {
		/* Call
		 */
		new_rule->operation = to_sub;

		if (rest == NULL) {
			return false;
		} else if ((new_rule->parameter = strdup(rest)) == NULL) {
			return false;
		}
	} else if (strcasecmp(value, "denyaccess") == 0) {
		/* Deny access
		 */
		new_rule->operation = to_deny_access;
		new_rule->flow = tf_exit;
	} else if (strcasecmp(value, "omitrequestlog") == 0) {
		/* Omit request log
		 */
		new_rule->operation = to_omit_request_log;
	} else if (strcasecmp(value, "exit") == 0) {
		/* Exit
		 */
		new_rule->flow = tf_exit;
	} else if (strcasecmp(value, "goto") == 0) {
		/* Goto
		 */
		new_rule->operation = to_sub;
		new_rule->flow = tf_exit;

		if (rest == NULL) {
			return false;
		} else if ((new_rule->parameter = strdup(rest)) == NULL) {
			return false;
		}
	} else if (strcasecmp(value, "notfound") == 0) {
		/* Fake a not found
		 */
		new_rule->operation = to_not_found;
		new_rule->flow = tf_exit;
	} else if (strcasecmp(value, "redirect") == 0) {
		/* Redirect
		 */
		new_rule->operation = to_redirect;
		new_rule->flow = tf_exit;

		if (rest == NULL) {
			return false;
		}

		split_string(rest, &value, &rest, ' ');

		if (rest != NULL) {
			new_rule->value = str_to_int(value);
			if ((new_rule->value < 301) || (new_rule->value > 308)) {
				return false;
			}

			value = rest;
		} else {
			new_rule->value = 301;
		}

		if ((new_rule->parameter = strdup(value)) == NULL) {
			return false;
		}
	} else if (strcasecmp(value, "return") == 0) {
		/* Return
		 */
		new_rule->flow = tf_return;
	} else if (strcasecmp(value, "rewrite") == 0) {
		/* Rewrite
		 */
		new_rule->operation = to_rewrite;
		new_rule->flow = tf_exit;

		split_string(rest, &value, &rest, ' ');
		if (value == NULL) {
			return false;
		} else if ((new_rule->parameter = strdup(value)) == NULL) {
			return false;
		}

		if (rest != NULL) {
			split_string(rest, &value, &rest, ' ');
			if ((loop = str_to_int(value)) > 0) {
				if (loop > MAX_MATCH_LOOP) {
					return false;
				}
				new_rule->match_loop = loop;
				if ((value = rest) == NULL) {
					return true;
				}
			} else if (rest != NULL) {
				return false;
			}

			if (strcasecmp(value, "continue") == 0) {
				new_rule->flow = tf_continue;
			} else if (strcasecmp(value, "return") == 0) {
				new_rule->flow = tf_return;
			} else {
				return false;
			}
		}
	} else if (strcasecmp(value, "skip") == 0) {
		/* Skip
		 */
		new_rule->operation = to_skip;

		if ((new_rule->value = str_to_int(rest)) < 1) {
			return false;
		}
	} else if (strcasecmp(value, "use") == 0) {
		/* Use
		 */
		new_rule->operation = to_use;
		new_rule->flow = tf_exit;

		if (valid_uri(rest, false) == false) {
			return false;
		} else if ((new_rule->parameter = strdup(rest)) == NULL) {
			return false;
		}
	} else if (strcasecmp(value, "usefastcgi") == 0) {
		/* UseFastCGI
		 */
		new_rule->operation = to_fastcgi;
		new_rule->flow = tf_exit;

		if (rest == NULL) {
			return false;
		} else if ((new_rule->parameter = strdup(rest)) == NULL) {
			return false;
		}
	} else {
		/* Error
		 */
		return false;
	}

	return true;
}

bool toolkit_setting(char *key, char *value, t_url_toolkit *toolkit) {
	t_toolkit_rule *new_rule, *rule;
	char *rest;
	int cflags;
	size_t len;
	char *do_operations[] = {
		"ban", "call", "denyaccess", "exit", "goto", "notfound", "omitrequestlog",
		"return", "skip", "use", NULL};
	char *header_operations[] = {
		"ban", "call", "denyaccess", "exit", "goto", "notfound", "omitrequestlog",
		"return", "skip", "use", NULL};
	char *match_operations[] = {
		"ban", "call", "denyaccess", "exit", "goto", "notfound", "redirect", "return",
		"rewrite", "skip", "usefastcgi", NULL};
	char *method_operations[] = {
		"call", "denyaccess", "exit", "goto", "notfound", "return", "skip", "use", NULL};
	char *requesturi_operations[] = {
		"call", "exit", "return", "skip", NULL};
	char *total_connections_operations[] = {
		"call", "goto", "omitrequestlog", "redirect", "skip", NULL};
#ifdef ENABLE_TLS
	char *usetls_operations[] = {
		"call", "exit", "goto", "return", "skip", NULL};
#endif

	if ((key == NULL) || (value == NULL) || (toolkit == NULL)) {
		return false;
	}

	if (strcmp(key, "toolkitid") == 0) {
		return (toolkit->toolkit_id = strdup(value)) != NULL;
	}

	if ((new_rule = (t_toolkit_rule*)malloc(sizeof(t_toolkit_rule))) == NULL) {
		return false;
	} else if (toolkit->toolkit_rule == NULL) {
		toolkit->toolkit_rule = new_rule;
	} else {
		rule = toolkit->toolkit_rule;
		while (rule->next != NULL) {
			rule = rule->next;
		}
		rule->next = new_rule;
	}

	new_rule->condition = tc_none;
	new_rule->operation = to_none;
	new_rule->flow = tf_continue;
	new_rule->match_loop = 1;
	new_rule->neg_match = false;
	new_rule->parameter = NULL;
	new_rule->header = NULL;
	new_rule->value = 0;
	new_rule->caco_private = true;
	new_rule->case_insensitive = false;
	new_rule->next = NULL;

	if (strcmp(key, "matchci") == 0) {
		new_rule->case_insensitive = true;
		key = "match";
	}

	if (strcmp(key, "do") == 0) {
		/* Do
		 */
		if (parse_parameters(new_rule, value, do_operations) == false) {
			return false;
		}
	} else if (strcmp(key, "header") == 0) {
		/* Header
		 */
		new_rule->condition = tc_header;

		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		}

		if (strcmp(value, "*") == 0) {
			new_rule->header = NULL;
		} else {
			len = strlen(value);
			if ((new_rule->header = (char*)malloc(len + 2)) == NULL) {
				return false;
			}
			sprintf(new_rule->header, "%s:", value);
		}

		if ((*rest == '\'') || (*rest == '"')) {
			value = rest + 1;
			if ((rest = strchr(rest + 1, *rest)) == NULL) {
				return false;
			}
			*rest = '\0';
			rest = remove_spaces(rest + 1);
		} else if (split_string(rest, &value, &rest, ' ') == -1) {
			return false;
		}

		if (*value == '!') {
			new_rule->neg_match = true;
			value++;
		}
		if (regcomp(&(new_rule->pattern), value, REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) {
			return false;
		}

		if (parse_parameters(new_rule, rest, header_operations) == false) {
			return false;
		}
	} else if (strcmp(key, "match") == 0) {
		/* Match
		 */
		cflags = REG_EXTENDED;
		if (new_rule->case_insensitive) {
			cflags |= REG_ICASE;
		}

		new_rule->condition = tc_match;
		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		}
		if (*value == '!') {
			new_rule->neg_match = true;
			value++;
		}
		if (regcomp(&(new_rule->pattern), value, cflags) != 0) {
			return false;
		}

		if (parse_parameters(new_rule, rest, match_operations) == false) {
			return false;
		}
	} else if (strcasecmp(key, "method") == 0) {
		/* Method
		 */
		new_rule->condition = tc_method;
		new_rule->flow = tf_continue;

		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		}

		if (*value == '!') {
			new_rule->neg_match = true;
			value++;
		}

		if ((new_rule->parameter = strdup(value)) == NULL) {
			return false;
		}

		if (parse_parameters(new_rule, rest, method_operations) == false) {
			return false;
		}
	} else if (strcmp(key, "requesturi") == 0) {
		/* RequestURI
		 */
		new_rule->condition = tc_request_uri;

		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		}

		if (strcasecmp(value, "notfound") == 0) {
			new_rule->value = IU_NOTFOUND;
		} else if (strcasecmp(value, "exists") == 0) {
			new_rule->value = IU_EXISTS;
		} else if (strcasecmp(value, "isfile") == 0) {
			new_rule->value = IU_ISFILE;
		} else if (strcasecmp(value, "isdir") == 0) {
			new_rule->value = IU_ISDIR;
		} else {
			return false;
		}

		if (parse_parameters(new_rule, rest, requesturi_operations) == false) {
			return false;
		}
	} else if (strcmp(key, "totalconnections") == 0) {
		/* TotalConnections
		 */
		new_rule->condition = tc_total_connections;

		if (split_string(value, &value, &rest, ' ') == -1) {
			return false;
		}

		if ((new_rule->value = str_to_int(value)) == -1) {
			return false;
		}

		if (parse_parameters(new_rule, rest, total_connections_operations) == false) {
			return false;
		}
#ifdef ENABLE_TLS
	} else if ((strcmp(key, "usetls") == 0) || (strcmp(key, "usessl") == 0)) {
		/* UseTLS
		 */
		new_rule->condition = tc_use_tls;

		if (parse_parameters(new_rule, value, usetls_operations) == false) {
			return false;
		}
#endif
	} else {
		/* Unknown condition
		 */
		return false;
	}

	return true;
}

bool toolkit_rules_oke(t_url_toolkit *url_toolkit) {
	t_url_toolkit *toolkit;
	t_toolkit_rule *rule;

	toolkit = url_toolkit;
	while (toolkit != NULL) {
		if (toolkit->toolkit_id == NULL) {
			fprintf(stderr, "A ToolkitID is missing in an UrlToolkit section.\n");
			return false;
		}

		rule = toolkit->toolkit_rule;
		while (rule != NULL) {
			if (rule->operation == to_sub) {
				if (rule->parameter == NULL) {
					fprintf(stderr, "Missing parameter in toolkit rule '%s'.\n", toolkit->toolkit_id);
					return false;
				} else if (select_toolkit(rule->parameter, url_toolkit) == NULL) {
					fprintf(stderr, "Unknown ToolkitID in Goto/Call in toolkit rule '%s'.\n", toolkit->toolkit_id);
					return false;
				}
			}
			rule = rule->next;
		}
		toolkit = toolkit->next;
	}

	return true;
}

static int do_rewrite(char *url, regex_t *regexp, regmatch_t *pmatch, char *rep, char **new_url, int loop) {
	int ofs, len, i, n;
	char *repl, *c, *sub, *tmp;
	bool first_run = true;

	if ((url == NULL) || (regexp == NULL) || (rep == NULL) || (new_url == NULL)) {
		return -1;
	}

	*new_url = NULL;
	while (loop-- > 0) {
		if (first_run) {
			first_run = false;
		} else if (regexec(regexp, url, REGEXEC_NMATCH, pmatch, 0) == REG_NOMATCH) {
			break;
		}

		if ((ofs = pmatch[0].rm_so) == -1) {
			return -1;
		}

		if ((repl = strdup(rep)) == NULL) {
			return -1;
		}

		/* Replace '$x' in replacement string with substring.
		 */
		c = repl;
		while (*c != '\0') {
			if (*c == '$') {
				if ((*(c + 1) >= '0') && (*(c + 1) <= '9')) {
					i = *(c + 1) - '0';
					if (pmatch[i].rm_so != -1) {
						len = pmatch[i].rm_eo - pmatch[i].rm_so;
						if ((sub = strdup(url + pmatch[i].rm_so)) == NULL) {
							free(repl);
							return -1;
						}
						sub[len] = '\0';
					} else {
						if ((sub = strdup("")) == NULL) {
							free(repl);
							return -1;
						}
					}
					n = c - repl;

					if (replace(repl, n, 2, sub, &tmp) == -1) {
						free(repl);
						free(sub);
						return -1;
					}

					free(repl);
					repl = tmp;
					c = repl + n + strlen(sub) - 1;
					free(sub);
				}
			}
			c++;
		}

		/* Replace pattern with replacement string.
		 */
		len = pmatch[0].rm_eo - ofs;
		if (replace(url, ofs, len, repl, new_url) == -1) {
			free(repl);
			return -1;
		}
		url = *new_url;

		free(repl);
	}

	return 0;
}

void init_toolkit_options(t_toolkit_options *options) {
	options->sub_depth = 0;
	options->new_url = NULL;
	options->method = NULL;
	options->website_root = NULL;
	options->fastcgi_server = NULL;
	options->ban = 0;
	options->caco_private = false;
	options->total_connections = 0;
#ifdef ENABLE_TLS
	options->use_tls = false;
#endif
	options->allow_dot_files = false;
	options->url_toolkit = NULL;
	options->http_headers = NULL;
}

int use_toolkit(char *url, t_url_toolkit *toolkit, t_toolkit_options *options) {
	t_url_toolkit *sub_toolkit;
	t_toolkit_rule *rule;
	bool condition_met, url_replaced = false;
	int result, skip = 0;
	char *file, *qmark, *header;
	regmatch_t pmatch[REGEXEC_NMATCH];
	struct stat fileinfo;
	t_http_header *headers;

	if (options == NULL) {
		return UT_ERROR;
	}

	options->new_url = NULL;

	rule = toolkit->toolkit_rule;
	while (rule != NULL) {
		condition_met = false;

		/* Skip lines
		 */
		if (skip > 0) {
			skip--;
			rule = rule->next;
			continue;
		}

		/* Condition
		 */
		switch (rule->condition) {
			case tc_none:
				/* None
				 */
				condition_met = true;
				break;
			case tc_match:
				/* Match
				 */
				if (regexec(&(rule->pattern), url, REGEXEC_NMATCH, pmatch, 0) == 0) {
					condition_met = true;
				}
				if (rule->neg_match) {
					condition_met = (condition_met == false);
				}
				break;
			case tc_header:
				/* Header
				 */
				if (rule->header == NULL) {
					/* Check all headers (wildcard)
					 */
					headers = options->http_headers;
					while (headers != NULL) {
						if (regexec(&(rule->pattern), headers->data + headers->value_offset, REGEXEC_NMATCH, pmatch, 0) == 0) {
							condition_met = true;
						}
						if (rule->neg_match) {
							condition_met = (condition_met == false);
						}

						if (condition_met) {
							break;
						}

						headers = headers->next;
					}
				} else {
					/* Check specific header
					 */
					if ((header = get_http_header(rule->header, options->http_headers)) != NULL) {
						if (regexec(&(rule->pattern), header, REGEXEC_NMATCH, pmatch, 0) == 0) {
							condition_met = true;
						}
					}
					if (rule->neg_match) {
						condition_met = (condition_met == false);
					}
				}
				break;
			case tc_method:
				/* Request method
				 */
				if (strcmp(options->method, rule->parameter) == 0) {
					condition_met = true;
				}
				if (rule->neg_match) {
					condition_met = (condition_met == false);
				}
				break;
			case tc_request_uri:
				/* Request URI
				 */
				if (valid_uri(url, options->allow_dot_files) == false) {
					break;
				}
				if ((file = make_path(options->website_root, url)) == NULL) {
					return UT_ERROR;
				}

				if ((qmark = strchr(file, '?')) != NULL) {
					*qmark = '\0';
				}
				url_decode(file);

				if (stat(file, &fileinfo) != -1) {
					switch (rule->value) {
						case IU_EXISTS:
							if (S_ISDIR(fileinfo.st_mode) || S_ISREG(fileinfo.st_mode)) {
								condition_met = true;
							}
							break;
						case IU_ISFILE:
							if (S_ISREG(fileinfo.st_mode)) {
								condition_met = true;
							}
							break;
						case IU_ISDIR:
							if (S_ISDIR(fileinfo.st_mode)) {
								condition_met = true;
							}
							break;
					}
				} else if ((errno == ENOENT) && (rule->value == IU_NOTFOUND)) {
					condition_met = true;
				}

				free(file);
				break;
			case tc_total_connections:
				/* Total connections reached?
				 */
				condition_met = options->total_connections >= rule->value;
				break;
#ifdef ENABLE_TLS
			case tc_use_tls:
				/* Client connections uses TLS?
				 */
				condition_met = options->use_tls;
				break;
#endif
		}

		/* Condition not met
		 */
		if (condition_met == false) {
			rule = rule->next;
			continue;
		}

		/* Operation
		 */
		switch (rule->operation) {
			case to_none:
				/* None
				 */
				break;
			case to_ban:
				/* Ban client
				 */
				options->ban = rule->value;
				break;
			case to_deny_access:
				/* Deny access
				 */
				return UT_DENY_ACCESS;
			case to_omit_request_log:
				/* Omit requeest log
				 */
				options->log_request = false;
				break;
			case to_fastcgi:
				/* Use FastCGI server
				 */
				options->fastcgi_server = rule->parameter;
				break;
			case to_not_found:
				/* Fake a not found
				 */
				return UT_NOT_FOUND;
			case to_redirect:
				/* Redirect client
				 */
				if (rule->neg_match) {
					if ((options->new_url = strdup(rule->parameter)) == NULL) {
						return UT_ERROR;
					}
				} else if (do_rewrite(url, &(rule->pattern), pmatch, rule->parameter, &(options->new_url), rule->match_loop) == -1) {
					if (options->new_url != NULL) {
						free(options->new_url);
						options->new_url = NULL;
					}
					return UT_ERROR;
				}
				if (options->new_url != NULL) {
					if (url_replaced) {
						free(url);
					}
					options->status_code = rule->value;
					return UT_REDIRECT;
				} else if (url_replaced) {
					options->new_url = url;
				}
				break;
			case to_rewrite:
				/* Rewrite
				 */
				if (rule->neg_match) {
					if ((options->new_url = strdup(rule->parameter)) == NULL) {
						return UT_ERROR;
					}
				} else if (do_rewrite(url, &(rule->pattern), pmatch, rule->parameter, &(options->new_url), rule->match_loop) == -1) {
					if (options->new_url != NULL) {
						free(options->new_url);
						options->new_url = NULL;
					}
					return UT_ERROR;
				}
				if (options->new_url != NULL) {
					if (url_replaced) {
						free(url);
					}
					url = options->new_url;
					url_replaced = true;
				} else if (url_replaced) {
					options->new_url = url;
				}
				break;
			case to_skip:
				/* Skip
				 */
				skip = rule->value;
				break;
			case to_sub:
				/* Subroutine
				 */
				if (++(options->sub_depth) > MAX_SUB_DEPTH) {
					return UT_ERROR;
				} else if ((sub_toolkit = select_toolkit(rule->parameter, options->url_toolkit)) == NULL) {
					return UT_ERROR;
				}

				if ((result = use_toolkit(url, sub_toolkit, options)) == UT_ERROR) {
					if (options->new_url != NULL) {
						free(options->new_url);
						options->new_url = NULL;
					}
					return UT_ERROR;
				}
				options->sub_depth--;

				if (options->new_url != NULL) {
					if (url_replaced) {
						free(url);
					}
					url = options->new_url;
					url_replaced = true;
				} else if (url_replaced) {
					options->new_url = url;
				}

				if (result != UT_RETURN) {
					return result;
				}
				break;
			case to_use:
				/* Replace URL
				 */
				if (url_replaced) {
					free(url);
				}
				if ((options->new_url = strdup(rule->parameter)) == NULL) {
					return UT_ERROR;
				}
				break;
		}

		/* Flow
		 */
		switch (rule->flow) {
			case tf_continue:
				/* Continue
				 */
				break;
			case tf_exit:
				/* Exit
				 */
				return UT_EXIT;
			case tf_return:
				/* Return
				 */
				return UT_RETURN;
		}

		rule = rule->next;
	}

	return UT_RETURN;
}

#endif
