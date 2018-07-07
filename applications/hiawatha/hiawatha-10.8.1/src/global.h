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

/* DON'T CHANGE THESE SETTINGS !!
 */
#ifndef _GLOBAL_H
#define _GLOBAL_H

#define KILOBYTE       1024
#define MEGABYTE    1048576
#define GIGABYTE 1073741824

#define MINUTE    60
#define HOUR    3600
#define DAY    86400

#define TASK_RUNNER_INTERVAL 10

#define TIMER_OFF   0

#define POLL_EVENT_BITS (POLLIN | POLLPRI | POLLHUP)

#define PTHREAD_STACK_SIZE 512 * KILOBYTE

#endif
