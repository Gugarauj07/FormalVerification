/*
 * acl_bypass_harness.c
 * Reproducao de CVE-2017-7650 (ACL bypass via wildcard em username).
 *
 * Funcoes copiadas literalmente da v1.4.10 (vulneravel) do Mosquitto:
 *   - mosquitto_topic_matches_sub  (lib/util_mosq.c)
 *   - mosquitto_acl_check_default  (src/security_default.c)
 *
 * Property (safety): se username != "victim", o ACL nao pode autorizar
 * leitura de "victim/data" sob o pattern "%u/data".
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define MOSQ_ERR_SUCCESS     0
#define MOSQ_ERR_INVAL       3
#define MOSQ_ERR_ACL_DENIED  12
#define MOSQ_ACL_READ        1
#define MOSQ_ACL_WRITE       2

struct _mosquitto_acl {
    char *topic;
    int   access;
    int   ucount;
    int   ccount;
    struct _mosquitto_acl *next;
};

struct _mosquitto_acl_user {
    char *username;
    struct _mosquitto_acl *acl;
    struct _mosquitto_acl_user *next;
};

struct mosquitto_db {
    struct _mosquitto_acl_user *acl_list;
    struct _mosquitto_acl      *acl_patterns;
};

struct mosquitto {
    char *id;
    char *username;
    void *bridge;
    struct _mosquitto_acl_user *acl_list;
};

#define _mosquitto_malloc malloc
#define _mosquitto_free   free

extern uint8_t __VERIFIER_nondet_uchar(void);

/* ===== COPIA LITERAL v1.4.10: lib/util_mosq.c ===== */
int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result)
{
    int slen, tlen;
    int spos, tpos;
    bool multilevel_wildcard = false;

    if(!sub || !topic || !result) return MOSQ_ERR_INVAL;

    slen = strlen(sub);
    tlen = strlen(topic);

    if(!slen || !tlen){
        *result = false;
        return MOSQ_ERR_INVAL;
    }

    if(slen && tlen){
        if((sub[0] == '$' && topic[0] != '$')
                || (topic[0] == '$' && sub[0] != '$')){
            *result = false;
            return MOSQ_ERR_SUCCESS;
        }
    }

    spos = 0;
    tpos = 0;

    while(spos < slen && tpos <= tlen){
        if(sub[spos] == topic[tpos]){
            if(tpos == tlen-1){
                if(spos == slen-3
                        && sub[spos+1] == '/'
                        && sub[spos+2] == '#'){
                    *result = true;
                    multilevel_wildcard = true;
                    return MOSQ_ERR_SUCCESS;
                }
            }
            spos++;
            tpos++;
            if(spos == slen && tpos == tlen){
                *result = true;
                return MOSQ_ERR_SUCCESS;
            }else if(tpos == tlen && spos == slen-1 && sub[spos] == '+'){
                if(spos > 0 && sub[spos-1] != '/'){
                    *result = false;
                    return MOSQ_ERR_INVAL;
                }
                spos++;
                *result = true;
                return MOSQ_ERR_SUCCESS;
            }
        }else{
            if(sub[spos] == '+'){
                if(spos > 0 && sub[spos-1] != '/'){
                    *result = false;
                    return MOSQ_ERR_INVAL;
                }
                if(spos < slen-1 && sub[spos+1] != '/'){
                    *result = false;
                    return MOSQ_ERR_INVAL;
                }
                spos++;
                while(tpos < tlen && topic[tpos] != '/'){
                    tpos++;
                }
                if(tpos == tlen && spos == slen){
                    *result = true;
                    return MOSQ_ERR_SUCCESS;
                }
            }else if(sub[spos] == '#'){
                if(spos > 0 && sub[spos-1] != '/'){
                    *result = false;
                    return MOSQ_ERR_INVAL;
                }
                multilevel_wildcard = true;
                if(spos+1 != slen){
                    *result = false;
                    return MOSQ_ERR_INVAL;
                }else{
                    *result = true;
                    return MOSQ_ERR_SUCCESS;
                }
            }else{
                *result = false;
                return MOSQ_ERR_SUCCESS;
            }
        }
    }
    if(multilevel_wildcard == false && (tpos < tlen || spos < slen)){
        *result = false;
    }

    return MOSQ_ERR_SUCCESS;
}

/* ===== COPIA LITERAL v1.4.10: src/security_default.c ===== */
int mosquitto_acl_check_default(struct mosquitto_db *db, struct mosquitto *context, const char *topic, int access)
{
    char *local_acl;
    struct _mosquitto_acl *acl_root;
    bool result;
    int i;
    int len, tlen, clen, ulen;
    char *s;

    if(!db || !context || !topic) return MOSQ_ERR_INVAL;
    if(!db->acl_list && !db->acl_patterns) return MOSQ_ERR_SUCCESS;
    if(context->bridge) return MOSQ_ERR_SUCCESS;
    if(!context->acl_list && !db->acl_patterns) return MOSQ_ERR_ACL_DENIED;

    if(context->acl_list){
        acl_root = context->acl_list->acl;
    }else{
        acl_root = NULL;
    }

    while(acl_root){
        if(topic[0] == '$' && acl_root->topic[0] != '$'){
            acl_root = acl_root->next;
            continue;
        }
        mosquitto_topic_matches_sub(acl_root->topic, topic, &result);
        if(result){
            if(access & acl_root->access){
                return MOSQ_ERR_SUCCESS;
            }
        }
        acl_root = acl_root->next;
    }

    acl_root = db->acl_patterns;
    clen = strlen(context->id);
    while(acl_root){
        tlen = strlen(acl_root->topic);

        if(acl_root->ucount && !context->username){
            acl_root = acl_root->next;
            continue;
        }

        if(context->username){
            ulen = strlen(context->username);
            len = tlen + acl_root->ccount*(clen-2) + acl_root->ucount*(ulen-2);
        }else{
            ulen = 0;
            len = tlen + acl_root->ccount*(clen-2);
        }
        local_acl = _mosquitto_malloc(len+1);
        if(!local_acl) return 1;
        s = local_acl;
        for(i=0; i<tlen; i++){
            if(i<tlen-1 && acl_root->topic[i] == '%'){
                if(acl_root->topic[i+1] == 'c'){
                    i++;
                    strncpy(s, context->id, clen);
                    s+=clen;
                    continue;
                }else if(context->username && acl_root->topic[i+1] == 'u'){
                    i++;
                    strncpy(s, context->username, ulen);
                    s+=ulen;
                    continue;
                }
            }
            s[0] = acl_root->topic[i];
            s++;
        }
        local_acl[len] = '\0';

        mosquitto_topic_matches_sub(local_acl, topic, &result);
        _mosquitto_free(local_acl);
        if(result){
            if(access & acl_root->access){
                return MOSQ_ERR_SUCCESS;
            }
        }

        acl_root = acl_root->next;
    }

    return MOSQ_ERR_ACL_DENIED;
}

/* ===== HARNESS ===== */

static char username_buf[2];

int main(void)
{
    uint8_t b = __VERIFIER_nondet_uchar();
    __ESBMC_assume(b >= 0x20 && b <= 0x7E);
    __ESBMC_assume(b != 'v');

    username_buf[0] = (char)b;
    username_buf[1] = '\0';

    static char pattern_topic[] = "%u/data";
    struct _mosquitto_acl pattern = {
        .topic  = pattern_topic,
        .access = MOSQ_ACL_READ,
        .ucount = 1,
        .ccount = 0,
        .next   = NULL,
    };
    struct mosquitto_db db = {
        .acl_list     = NULL,
        .acl_patterns = &pattern,
    };
    static char attacker_id[] = "attacker";
    struct mosquitto ctx = {
        .id        = attacker_id,
        .username  = username_buf,
        .bridge    = NULL,
        .acl_list  = NULL,
    };

    static char target_topic[] = "victim/data";
    int rc = mosquitto_acl_check_default(&db, &ctx, target_topic, MOSQ_ACL_READ);

    __ESBMC_assert(rc != MOSQ_ERR_SUCCESS,
        "CVE-2017-7650: ACL bypass - atacante ganhou READ em victim/data");

    return 0;
}
