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
 *
 * Implements the spambot keyword
 */
 
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-spambot.h"
#include "util-debug.h"

#include "host.h"

/*prototypes*/
int DetectSpambotMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectSpambotSetup (DetectEngineCtx *, Signature *, char *);
void DetectSpambotFree (void *);
void DetectSpambotRegisterTests (void);

/**
 * \brief Registration function for `spambot` keyword
 */

void DetectSpambotRegister(void) {
    sigmatch_table[DETECT_SPAMBOT].name = "spambot";
    sigmatch_table[DETECT_SPAMBOT].Match = DetectSpambotMatch;
    sigmatch_table[DETECT_SPAMBOT].Setup = DetectSpambotSetup;
    sigmatch_table[DETECT_SPAMBOT].Free = DetectSpambotFree;
    sigmatch_table[DETECT_SPAMBOT].RegisterTests = DetectSpambotRegisterTests;
}

/**
 * \brief This function is used to match packets via the spambot rule
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSpambotData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectSpambotMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m) {

    int ret = 0;
    DetectSpambotSig *dsig = (DetectSpambotSig *) m->ctx;
    DetectSpambotData *ddata;
    Host *h;

    if (PKT_IS_PSEUDOPKT(p)
        || !PKT_IS_IPV4(p)
        || p->flags & PKT_HOST_SRC_LOOKED_UP
        || p->payload_len == 0) {
        return 0;
    }

    /* TODO: Inspect the packet contents here.
     * Suricata defines a `Packet` structure in decode.h which already defines 
     * many useful elements -- have a look! */
	if(strstr((char *)p->payload, "RCPT TO:") == NULL) {
		return 0;
	}

    h = HostGetHostFromHash(&(p->src));
    p->flags |= PKT_HOST_SRC_LOOKED_UP;

    if (h == NULL) {
        printf("host not found!\n");
        return 0;
    }

    ddata = (DetectSpambotData *) h->spambot;
    if (!ddata) {
        /* initialize fresh spambotdata */
        ddata = SCMalloc(sizeof(DetectSpambotData));
        bzero(ddata, sizeof(DetectSpambotData));
        h->spambot = ddata;
    }
	
    (ddata->cnt_rcpt_to)++;
    // !!!DEBUG
	printf("\"RCPT TO:\" found, cnt_rcpt_to now %d\n", ddata->cnt_rcpt_to);
    ret = (ddata->cnt_rcpt_to > dsig->interval_peak_threshold);
    
    HostRelease(h);
    return ret;
}

/**
 * \brief this function is used to setup the spambot environment
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param spambotstr pointer to the user provided spambot options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSpambotSetup (DetectEngineCtx *de_ctx, Signature *s, char *spambotstr) {

    SigMatch *sm = NULL;
    DetectSpambotSig *dsig = NULL;
	
	char* tok;
	char* save;
	uint32_t tmp;
	
    dsig = SCMalloc(sizeof(DetectSpambotSig));
    if (dsig == NULL) { goto error; }

    sm = SigMatchAlloc();
    if (sm == NULL) { goto error; }
	
	tok = strtok(spambotstr,": ,");
	while (tok != NULL) {
		save = tok;
		tok = strtok(NULL, ": ,");
		if((tmp = atoi(tok)) == 0) {
			return -1;
		}
		
		if(strcmp(save, "interval_peak_threshold") == 0) {
			dsig->interval_peak_threshold = tmp;
		} else if(strcmp(save, "interval_length") == 0) {
			dsig->interval_length = tmp;
		} else if(strcmp(save, "anomaly_threshold") == 0) {
			dsig->anomaly_threshold = tmp;
		} else if(strcmp(save, "timespan_length") == 0) {
			dsig->timespan_length = tmp;
		}
		tok = strtok(NULL, ": ,");
	}
	
    sm->type = DETECT_SPAMBOT;
    sm->ctx = (void *) dsig;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (dsig != NULL) SCFree(dsig);
    if (sm != NULL) SCFree(sm);
    return -1;
}

void DetectSpambotFree (void *ptr) {
    DetectSpambotData *ed = (DetectSpambotData*) ptr;
    SCFree(ed);
}

void DetectSpambotRegisterTests(void) {
    #ifdef UNITTESTS
    // TODO
    #endif
}
