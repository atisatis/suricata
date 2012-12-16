/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Alexander Bueckig  <alexbueckig [at] gmail.com>, Maik Heidisch <maik [at] heidisch.de>
 */

#ifndef _DETECT_SPAMBOT_H
#define	_DETECT_SPAMBOT_H

#include <time.h>

typedef struct DetectSpambotSig_ {
    uint32_t interval_peak_threshold; /** < interval peak threshold */
	uint32_t interval_length; /** < interval length in seconds */
	uint32_t anomaly_threshold; /** < anomaly threshold */
	uint32_t timespan_length; /** < timespan length in seconds */
} DetectSpambotSig;

typedef struct DetectSpambotData_ {
	time_t begin_timespan;		/** < timestamp of start of timespan */
    uint32_t cnt_rcpt_to;		/** < number of "RCPT TO:" sent in interval */
	uint32_t cnt_violation;		/** < number of violation of anomaly_threshold in timespan */
} DetectSpambotData;

void DetectSpambotRegister(void);

#endif	/* _DETECT_SPAMBOT_H */

