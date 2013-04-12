#include <errno.h>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <libotr/proto.h>
#include <libotr/userstate.h>
#include <libotr/privkey.h>
#include <libotr/tlv.h>
#include <libotr/message.h>
#include <libotr/serial.h>

#include <android/log.h>

static JNIEnv* global_env = NULL;

#define OTRMODULE "otr/OtrModule"
#define APPNAME "OTRJNI"
#define printf(fmt,args...) __android_log_print(ANDROID_LOG_INFO, APPNAME, fmt, ##args)

#define JSTR_GET(X,Y) const jbyte *X##_str=(*env)->GetStringUTFChars(env, X, NULL);if(X##_str==NULL)return Y;
#define JSTR_RELEASE(X) (*env)->ReleaseStringUTFChars(env, X, X##_str)
#define JSTRINGIFY(X) (*env)->NewStringUTF(env,X)

static void init(){
	/* Version check should be the very first call because it
	          makes sure that important subsystems are initialized. */
	if (!gcry_check_version (GCRYPT_VERSION))
	{
	  printf("Wrong gcrypt library version!");
	  exit (2);
	}

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	OTRL_INIT;
	printf("libotr Initialised.");
}

void Java_otr_OtrModule_initialize(JNIEnv* env, jobject this) {
    if(global_env == NULL){
	    init();
    	global_env = env;
    }
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallMalloc(JNIEnv* env, jobject this, jint N){
    return malloc(N);
}
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallFree(JNIEnv* env, jobject this, jint ptr){
    free(ptr);
}
JNIEXPORT jstring JNICALL
Java_otr_OtrModule_CallStringify(JNIEnv* env, jobject this, jint ptr){
    return JSTRINGIFY(ptr);
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGetValueInt32(JNIEnv* env, jobject this, jint ptr){
    return (*((int*)ptr));
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGetValueInt16(JNIEnv* env, jobject this, jint ptr){
    return (*((short*)ptr));
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGetValueInt8(JNIEnv* env, jobject this, jint ptr){
    return (*((char*)ptr));
}
void
Java_otr_OtrModule_CallSetValueInt32(JNIEnv* env, jobject this, jint ptr, jint value){
    int* dest = (int*)ptr;
    *dest = value;
}
void
Java_otr_OtrModule_CallSetValueInt16(JNIEnv* env, jobject this, jint ptr, jshort value){
    short* dest = (short*)ptr;
    *dest = value;
}
void
Java_otr_OtrModule_CallSetValueInt8(JNIEnv* env, jobject this, jint ptr, jbyte value){
    char* dest = (char*)ptr;
    *dest = value;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGcryStrerror(JNIEnv* env, jobject this, jint err){
    return JSTRINGIFY(gcry_strerror(err));
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGcryMpiNew(JNIEnv* env, jobject this, jint n){
    return gcry_mpi_new(n);
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGcryMpiSet(JNIEnv* env, jobject this, jint mpi_a, jint mpi_b){
    return gcry_mpi_set(mpi_a,mpi_b);
}
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallGcryMpiRelease(JNIEnv* env, jobject this, jint mpi_a){
    gcry_mpi_release(mpi_a);
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGcryMpiScan(JNIEnv* env, jobject this, jint a, jint b, jstring c, jint d, jint e ){
    JSTR_GET(c,GPG_ERR_ENOMEM);
    gcry_error_t err = gcry_mpi_scan(a,b,c_str,d,e);
    JSTR_RELEASE(c);
    return err;
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallGcryMpiPrint(JNIEnv* env, jobject this, jint a, jint b, jint c, jint d, jint e){
    return gcry_mpi_print(a,b,c,d,e);
}

JNIEXPORT jstring JNICALL
Java_otr_OtrModule_CallOtrlVersion(JNIEnv* env, jobject this){
    return JSTRINGIFY(otrl_version());
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlUserstateCreate(JNIEnv* env, jobject this){
    return otrl_userstate_create();
}

void
Java_otr_OtrModule_CallOtrlUserstateFree(JNIEnv* env, jobject this, jint userstate){
    otrl_userstate_free(userstate);
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyRead(JNIEnv* env, jobject this, jint userstate, jstring filename){
    JSTR_GET(filename,GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_privkey_read(userstate,filename_str);
    JSTR_RELEASE(filename);
    return err;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyFingerprint(JNIEnv* env, jobject this, jint userstate,
        jint fingerprint, jstring username, jstring protocol){
    JSTR_GET(username,NULL);
    JSTR_GET(protocol,NULL);
    jint fp = otrl_privkey_fingerprint(userstate,(char*)fingerprint,username_str,protocol_str);
    JSTR_RELEASE(username); JSTR_RELEASE(protocol);
    return fp;
}

/*
gcry_error_t otrl_privkey_read_fingerprints(OtrlUserState us,
    const char *filename,
    void (*add_app_data)(void *data, ConnContext *context),
    void  *data);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyReadFingerprints(JNIEnv* env, jobject this, jint userstate,
        jstring filename, jint add_app_data, jint data){
    JSTR_GET(filename,GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_privkey_read_fingerprints(userstate,filename_str,add_app_data,data);
    JSTR_RELEASE(filename);
    return err;
}

/*
gcry_error_t otrl_privkey_write_fingerprints(OtrlUserState us,
    const char *filename);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyWriteFingerprints(JNIEnv* env, jobject this, jint userstate,
        jstring filename){
    JSTR_GET(filename,GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_privkey_write_fingerprints(userstate,filename_str);
    JSTR_RELEASE(filename);
    return err;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyGenerate(JNIEnv* env, jobject this, jint userstate,
        jstring filename, jstring username, jstring protocol){
    JSTR_GET(filename,GPG_ERR_ENOMEM);
    JSTR_GET(username,GPG_ERR_ENOMEM);
    JSTR_GET(protocol,GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_privkey_generate(userstate,filename_str,username_str,protocol_str);
    JSTR_RELEASE(filename);JSTR_RELEASE(username);JSTR_RELEASE(protocol);
    return err;
}

JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyForget(JNIEnv* env, jobject this, jint ptr){
    otrl_privkey_forget(ptr);
}

JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyForgetAll(JNIEnv* env, jobject this, jint ptr){
    otrl_privkey_forget_all(ptr);
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlPrivkeyFind(JNIEnv* env, jobject this, jint userstate, 
        jstring username, jstring protocol){
    JSTR_GET(username,NULL);
    JSTR_GET(protocol,NULL);
    OtrlPrivKey* key = otrl_privkey_find(userstate,username_str,protocol_str);
    JSTR_RELEASE(username);JSTR_RELEASE(protocol);
    return key;
}

/*
ConnContext * otrl_context_find(OtrlUserState us, const char *user,
    const char *accountname, const char *protocol,
    otrl_instag_t their_instance, int add_if_missing, int *addedp,
    void (*add_app_data)(void *data, ConnContext *context), void *data);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlContextFind(JNIEnv* env, jobject this, jint userstate, jstring user,
        jstring username, jstring protocol,
        jint their_instance, jint add_if_missing, jint addedp, jint add_appdata, jint data ){
    JSTR_GET(username,NULL);
    JSTR_GET(protocol,NULL);
    JSTR_GET(user,NULL);
    ConnContext* ctx = otrl_context_find(userstate,user_str,username_str,protocol_str,
        their_instance, add_if_missing, addedp, add_appdata, data );
    JSTR_RELEASE(username);JSTR_RELEASE(protocol);JSTR_RELEASE(user);
    return ctx;
}
/*
gcry_error_t otrl_message_sending(OtrlUserState us,
    const OtrlMessageAppOps *ops,
    void *opdata, const char *accountname, const char *protocol,
    const char *recipient, otrl_instag_t instag, const char *original_msg,
    OtrlTLV *tlvs, char **messagep, OtrlFragmentPolicy fragPolicy,
    ConnContext **contextp,
    void (*add_appdata)(void *data, ConnContext *context),
    void *data);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlMessageSending(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jstring accountname, jstring protocol,
        jstring recipient, jint instag, jstring original_msg,
        jint tlvs, jint messagep, jint fragPolicy, jint contextp,
        jint add_appdata, jint data){
    JSTR_GET(accountname,GPG_ERR_ENOMEM);
    JSTR_GET(protocol,GPG_ERR_ENOMEM);
    JSTR_GET(recipient,GPG_ERR_ENOMEM);
    JSTR_GET(original_msg,GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_message_sending(userstate,ops,opdata,accountname_str,protocol_str,recipient_str,instag,
        original_msg_str, tlvs, messagep, fragPolicy, contextp,add_appdata,data);
    JSTR_RELEASE(accountname);JSTR_RELEASE(protocol);JSTR_RELEASE(recipient);JSTR_RELEASE(original_msg);
    return err;
}

/*
int otrl_message_receiving(OtrlUserState us, const OtrlMessageAppOps *ops,
    void *opdata, const char *accountname, const char *protocol,
    const char *sender, const char *message, char **newmessagep,
    OtrlTLV **tlvsp, ConnContext **contextp,
    void (*add_appdata)(void *data, ConnContext *context),
    void *data);
*/

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlMessageReceiving(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jstring accountname, jstring protocol,
        jstring sender, jstring message, jint newmessagep,
        jint tlvsp, jint contextp,
        jint add_appdata, jint data){
    JSTR_GET(accountname,GPG_ERR_ENOMEM);
    JSTR_GET(protocol,GPG_ERR_ENOMEM);
    JSTR_GET(sender,GPG_ERR_ENOMEM);
    JSTR_GET(message,GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_message_receiving(userstate,ops,opdata,accountname_str,protocol_str,sender_str,
        message_str, newmessagep,tlvsp,contextp,add_appdata,data);
    JSTR_RELEASE(accountname);JSTR_RELEASE(protocol);JSTR_RELEASE(sender);JSTR_RELEASE(message);
    return err;
}

JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageFree(JNIEnv* env, jobject this, jint ptr){
    otrl_message_free(ptr);
}

/*
void otrl_message_disconnect(OtrlUserState us, const OtrlMessageAppOps *ops,
    void *opdata, const char *accountname, const char *protocol,
    const char *username, otrl_instag_t instance);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageDisconnect(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jstring accountname, jstring protocol,
        jstring username, jint instance){
    JSTR_GET(accountname, );
    JSTR_GET(protocol, );
    JSTR_GET(username, );
    otrl_message_disconnect(userstate,ops,opdata,accountname_str,protocol_str,username_str,instance);
    JSTR_RELEASE(accountname);JSTR_RELEASE(protocol);JSTR_RELEASE(username);
}

/*
void otrl_message_disconnect_all_instances(OtrlUserState us,
    const OtrlMessageAppOps *ops, void *opdata, const char *accountname,
    const char *protocol, const char *username);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageDisconnectAllInstances(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jstring accountname, jstring protocol,
        jstring username){
    JSTR_GET(accountname, );
    JSTR_GET(protocol, );
    JSTR_GET(username, );
    otrl_message_disconnect_all_instances(userstate,ops,opdata, accountname_str,protocol_str,username_str);
    JSTR_RELEASE(accountname);JSTR_RELEASE(protocol);JSTR_RELEASE(username);
}
/*
void otrl_message_initiate_smp(OtrlUserState us, const OtrlMessageAppOps *ops,
    void *opdata, ConnContext *context, const unsigned char *secret,
    size_t secretlen);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageInitiateSmp(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jint context, jstring secret, jint secretlen){
    JSTR_GET(secret, );
    otrl_message_initiate_smp(userstate, ops, opdata,context,secret_str,secretlen);
    JSTR_RELEASE(secret);
}

/*
void otrl_message_initiate_smp_q(OtrlUserState us,
    const OtrlMessageAppOps *ops, void *opdata, ConnContext *context,
    const char *question, const unsigned char *secret, size_t secretlen);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageInitiateSmpQ(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jint context, jstring question, jstring secret, jint secretlen){
    JSTR_GET(question, );
    JSTR_GET(secret, );
    otrl_message_initiate_smp_q(userstate, ops, opdata,context,question_str, secret_str,secretlen);
    JSTR_RELEASE(question);JSTR_RELEASE(secret);
}

/*
void otrl_message_respond_smp(OtrlUserState us, const OtrlMessageAppOps *ops,
    void *opdata, ConnContext *context, const unsigned char *secret,
    size_t secretlen);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageRespondSmp(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jint context, jstring secret, jint secretlen){
    JSTR_GET(secret, );
    otrl_message_respond_smp(userstate, ops, opdata,context,secret_str,secretlen);
    JSTR_RELEASE(secret);
}

/*
void otrl_message_abort_smp(OtrlUserState us, const OtrlMessageAppOps *ops,
    void *opdata, ConnContext *context);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlMessageAbortSmp(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jint context){
    otrl_message_abort_smp(userstate, ops, opdata,context);
}

/*
gcry_error_t otrl_message_symkey(OtrlUserState us,
    const OtrlMessageAppOps *ops, void *opdata, ConnContext *context,
    unsigned int use, const unsigned char *usedata, size_t usedatalen,
    unsigned char *symkey);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlMessageSymkey(JNIEnv* env, jobject this, jint userstate,
        jint ops, jint opdata, jint context, jint use, jint usedata, jint usedatalen, jint symkey){
    return otrl_message_symkey(userstate, ops, opdata,context,use,usedata,usedatalen,symkey);
}

/*
OtrlInsTag * otrl_instag_find(OtrlUserState us, const char *accountname,
    const char *protocol);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlInstagFind(JNIEnv* env, jobject this, jint userstate,
        jstring accountname, jstring protocol){
    JSTR_GET(accountname, NULL);
    JSTR_GET(protocol, NULL);
    OtrlInsTag* instag = otrl_instag_find(userstate, accountname_str, protocol_str);
    JSTR_RELEASE(accountname);JSTR_RELEASE(protocol);
    return instag;
}

/*
gcry_error_t otrl_instag_read(OtrlUserState us, const char *filename);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlInstagRead(JNIEnv* env, jobject this, jint userstate,
        jstring filename){
    JSTR_GET(filename, GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_instag_read(userstate, filename_str);
    JSTR_RELEASE(filename);
    return err;
}

/*
gcry_error_t otrl_instag_write(OtrlUserState us, const char *filename);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlInstagWrite(JNIEnv* env, jobject this, jint userstate,
        jstring filename){
    JSTR_GET(filename, GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_instag_write(userstate, filename_str);
    JSTR_RELEASE(filename);
    return err;
}
/*
gcry_error_t otrl_instag_generate(OtrlUserState us, const char *filename,
    const char *accountname, const char *protocol);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlInstagGenerate(JNIEnv* env, jobject this, jint userstate, jstring filename,
        jstring accountname, jstring protocol){
    JSTR_GET(filename, GPG_ERR_ENOMEM);
    JSTR_GET(accountname, GPG_ERR_ENOMEM);
    JSTR_GET(protocol, GPG_ERR_ENOMEM);
    gcry_error_t err = otrl_instag_generate(userstate, filename_str, accountname_str, protocol_str);
    JSTR_RELEASE(filename); JSTR_RELEASE(accountname);JSTR_RELEASE(protocol);
    return err;
}

/*
void otrl_tlv_free(OtrlTLV *tlv);
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallOtrlTlvFree(JNIEnv* env, jobject this, jint tlv){
    otrl_tlv_free(tlv);
}

/*
OtrlTLV *otrl_tlv_find(OtrlTLV *tlvs, unsigned short type);
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallOtrlTlvFind(JNIEnv* env, jobject this, jint tlvs, jint type){
    return otrl_tlv_find(tlvs,type);
}

////// jsapi.c ////////

/*
OtrlPrivKey* jsapi_userstate_get_privkey_root(OtrlUserState us){
    return us->privkey_root;
}
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiUserstateGetPrivkeyRoot(JNIEnv* env, jobject this, jint us){
    return ((OtrlUserState)us)->privkey_root;
}
/*
OtrlPrivKey* jsapi_privkey_get_next(OtrlPrivKey* p){
    return p->next;
}
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiUserstateGetPrivkeyNext(JNIEnv* env, jobject this, jint p){
    return ((OtrlPrivKey*)p)->next;
}
/*
char* jsapi_privkey_get_accountname(OtrlPrivKey* p){
    return p->accountname;
}
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiUserstateGetPrivkeyAccountname(JNIEnv* env, jobject this, jint p){
    return JSTRINGIFY(((OtrlPrivKey*)p)->accountname);
}

/*
char* jsapi_privkey_get_protocol(OtrlPrivKey* p){
    return p->protocol;
}
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiPrivkeyGetProtocol(JNIEnv* env, jobject this, jint p){
    return ((OtrlPrivKey*)p)->protocol;
}

static gcry_error_t jsapi_privkey_write_trusted_fingerprints_FILEp(OtrlUserState us, FILE *storef){
    ConnContext *context;
    Fingerprint *fprint;

    if (!storef) return gcry_error(GPG_ERR_NO_ERROR);

    for(context = us->context_root; context; context = context->next) {
    /* Fingerprints are only stored in the master contexts */
    if (context->their_instance != OTRL_INSTAG_MASTER) continue;

    /* Don't bother with the first (fingerprintless) entry. */
    for (fprint = context->fingerprint_root.next; fprint && fprint->trust;
        fprint = fprint->next) {
        int i;
        fprintf(storef, "%s\t%s\t%s\t", context->username,
            context->accountname, context->protocol);
        for(i=0;i<20;++i) {
        fprintf(storef, "%02x", fprint->fingerprint[i]);
        }
        fprintf(storef, "\t%s\n", fprint->trust ? fprint->trust : "");
    }
    }

    return gcry_error(GPG_ERR_NO_ERROR);
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiPrivkeyWriteTrustedFingerprints(JNIEnv* env, jobject this, jint userstate, jstring filename){
    OtrlUserState us = (OtrlUserState)userstate;
    gcry_error_t err;
    FILE *storef;
    JSTR_GET(filename, GPG_ERR_ENOMEM);

    storef = fopen(filename_str, "wb");
    JSTR_RELEASE(filename);

    if (!storef) {
    err = gcry_error_from_errno(errno);
    return err;
    }

    err = jsapi_privkey_write_trusted_fingerprints_FILEp(us, storef);

    fclose(storef);
    return err;
}

static gcry_error_t jsapi_sexp_write(FILE *privf, gcry_sexp_t sexp)
{
    size_t buflen;
    char *buf;

    buflen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = malloc(buflen);
    if (buf == NULL && buflen > 0) {
	return gcry_error(GPG_ERR_ENOMEM);
    }
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, buflen);

    fprintf(privf, "%s", buf);
    free(buf);

    return gcry_error(GPG_ERR_NO_ERROR);
}

static gcry_error_t jsapi_account_write(FILE *privf, const char *accountname,
	const char *protocol, gcry_sexp_t privkey)
{
    gcry_error_t err;
    gcry_sexp_t names, protos;

    fprintf(privf, " (account\n");

    err = gcry_sexp_build(&names, NULL, "(name %s)", accountname);
    if (!err) {
	err = jsapi_sexp_write(privf, names);
	gcry_sexp_release(names);
    }
    if (!err) err = gcry_sexp_build(&protos, NULL, "(protocol %s)", protocol);
    if (!err) {
	err = jsapi_sexp_write(privf, protos);
	gcry_sexp_release(protos);
    }
    if (!err) err = jsapi_sexp_write(privf, privkey);

    fprintf(privf, " )\n");

    return err;
}

gcry_error_t jsapi_userstate_write_to_file(OtrlUserState us, const char *filename){
    gcry_error_t err = GPG_ERR_NO_ERROR;
    FILE *privf;
    OtrlPrivKey *p;
    mode_t oldmask;
    oldmask = umask(077);

    privf = fopen(filename, "w+b");

    if (!privf) {
        umask(oldmask);
    	err = gcry_error_from_errno(errno);
    	return err;
    }

    /* Output all the keys we know ...*/
    fprintf(privf, "(privkeys\n");

    for (p=us->privkey_root; p; p=p->next) {
	    jsapi_account_write(privf, p->accountname, p->protocol, p->privkey);
    }

    fprintf(privf, ")\n");
    fseek(privf, 0, SEEK_SET);
    fclose(privf);

    umask(oldmask);
    return err;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiUserstateWriteToFile(JNIEnv* env, jobject this, jint userstate, jstring filename){
    JSTR_GET(filename, GPG_ERR_ENOMEM);
    gcry_error_t err= jsapi_userstate_write_to_file(userstate,filename_str);
    JSTR_RELEASE(filename);
    return err;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiPrivkeyDelete(JNIEnv* env, jobject this, jint userstate, jstring filename,
        jstring accountname, jstring protocol){
    JSTR_GET(filename, GPG_ERR_ENOMEM);
    JSTR_GET(accountname, GPG_ERR_ENOMEM);
    JSTR_GET(protocol, GPG_ERR_ENOMEM);
    OtrlUserState us = (OtrlUserState)userstate;
    gcry_error_t err = 0;

    /* remove key from userstate */
    OtrlPrivKey* existing_key = otrl_privkey_find(us,accountname_str,protocol_str);
    if( existing_key ){
        otrl_privkey_forget(existing_key);
        err = jsapi_userstate_write_to_file(us, filename_str);//write out the changes
    }
    JSTR_RELEASE(filename); JSTR_RELEASE(accountname); JSTR_RELEASE(protocol);
    return err;
}

/*
gcry_error_t
jsapi_privkey_get_dsa_token(OtrlPrivKey *keyToExport, const char* token,
            unsigned char *buffer, size_t buflen, size_t *nbytes)
*/
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiPrivkeyGetDsaToken(JNIEnv* env, jobject this, jint keyToExportPtr, jstring token,
            jint buffer, jint buflen, jint nbytes)
{
    OtrlPrivKey *keyToExport = (OtrlPrivKey*)keyToExportPtr;
    JSTR_GET(token, GPG_ERR_ENOMEM);
    gcry_error_t err;
    gcry_mpi_t x;
    gcry_sexp_t dsas,xs;
    size_t nx;

    gcry_sexp_t privkey = keyToExport->privkey;

    dsas = gcry_sexp_find_token(privkey, "dsa", 0);
    if (dsas == NULL) {
        JSTR_RELEASE(token);
        return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }

    xs = gcry_sexp_find_token(dsas, token_str, 0);
    gcry_sexp_release(dsas);
    JSTR_RELEASE(token);

    if (!xs) return gcry_error(GPG_ERR_UNUSABLE_SECKEY);

    x = gcry_sexp_nth_mpi(xs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(xs);

    if (!x) return gcry_error(GPG_ERR_UNUSABLE_SECKEY);

    err =  gcry_mpi_print(GCRYMPI_FMT_HEX, buffer,buflen,nbytes,x);
    gcry_mpi_release(x);
    return err;
}
//copy of make_pubkey() from libotr3.2.1/src/privkey.c
/* Create a public key block from a private key */
static gcry_error_t jsapi_make_pubkey(unsigned char **pubbufp, size_t *publenp,
	gcry_sexp_t privkey)
{
    gcry_mpi_t p,q,g,y;
    gcry_sexp_t dsas,ps,qs,gs,ys;
    size_t np,nq,ng,ny;
    enum gcry_mpi_format format = GCRYMPI_FMT_USG;
    unsigned char *bufp;
    size_t lenp;

    *pubbufp = NULL;
    *publenp = 0;

    /* Extract the public parameters */
    dsas = gcry_sexp_find_token(privkey, "dsa", 0);
    if (dsas == NULL) {
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    ps = gcry_sexp_find_token(dsas, "p", 0);
    qs = gcry_sexp_find_token(dsas, "q", 0);
    gs = gcry_sexp_find_token(dsas, "g", 0);
    ys = gcry_sexp_find_token(dsas, "y", 0);
    gcry_sexp_release(dsas);
    if (!ps || !qs || !gs || !ys) {
	gcry_sexp_release(ps);
	gcry_sexp_release(qs);
	gcry_sexp_release(gs);
	gcry_sexp_release(ys);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }
    p = gcry_sexp_nth_mpi(ps, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ps);
    q = gcry_sexp_nth_mpi(qs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(qs);
    g = gcry_sexp_nth_mpi(gs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(gs);
    y = gcry_sexp_nth_mpi(ys, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ys);
    if (!p || !q || !g || !y) {
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }

    *publenp = 0;
    gcry_mpi_print(format, NULL, 0, &np, p);
    *publenp += np + 4;
    gcry_mpi_print(format, NULL, 0, &nq, q);
    *publenp += nq + 4;
    gcry_mpi_print(format, NULL, 0, &ng, g);
    *publenp += ng + 4;
    gcry_mpi_print(format, NULL, 0, &ny, y);
    *publenp += ny + 4;

    *pubbufp = malloc(*publenp);
    if (*pubbufp == NULL) {
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	return gcry_error(GPG_ERR_ENOMEM);
    }
    bufp = *pubbufp;
    lenp = *publenp;

    write_mpi(p,np,"P");
    write_mpi(q,nq,"Q");
    write_mpi(g,ng,"G");
    write_mpi(y,ny,"Y");

    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);

    return gcry_error(GPG_ERR_NO_ERROR);
}


gcry_error_t jsapi_userstate_import_privkey(OtrlUserState us, char *accountname, char * protocol, 
                    gcry_mpi_t p, gcry_mpi_t q, gcry_mpi_t g, gcry_mpi_t y, gcry_mpi_t x){
    size_t *erroff;
    const char *token;
    size_t tokenlen;
    gcry_error_t err;
    gcry_sexp_t allkeys;
    size_t i;

    //puts("jsapi_userstate_import_privkey: building sexp");

    err = gcry_sexp_build(&allkeys,erroff,"(privkeys (account (name %s) (protocol %s) (private-key (dsa \
        (p %M) (q %M) (g %M) (y %M) (x %M) ))))",accountname,protocol,p,q,g,y,x);

    if(err) return err;

    /* forget existing account/key */
    OtrlPrivKey* existing_key = otrl_privkey_find(us,accountname,protocol);
    if( existing_key) otrl_privkey_forget(existing_key);

    //puts("getting allkeys from sexp");

    token = gcry_sexp_nth_data(allkeys, 0, &tokenlen);
    if (tokenlen != 8 || strncmp(token, "privkeys", 8)) {
	    gcry_sexp_release(allkeys);
	    return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
    }

    /* Get each account */
    for(i=1; i<gcry_sexp_length(allkeys); ++i) {

	    gcry_sexp_t names, protos, privs;
	    char *name, *proto;
	    gcry_sexp_t accounts;
	    OtrlPrivKey *p;

	    /* Get the ith "account" S-exp */
	    accounts = gcry_sexp_nth(allkeys, i);

	    /* It's really an "account" S-exp? */
	    token = gcry_sexp_nth_data(accounts, 0, &tokenlen);
	    if (tokenlen != 7 || strncmp(token, "account", 7)) {
	        gcry_sexp_release(accounts);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
	    }
	    /* Extract the name, protocol, and privkey S-exps */
	    names = gcry_sexp_find_token(accounts, "name", 0);
	    protos = gcry_sexp_find_token(accounts, "protocol", 0);
	    privs = gcry_sexp_find_token(accounts, "private-key", 0);
	    gcry_sexp_release(accounts);
	    if (!names || !protos || !privs) {
	        gcry_sexp_release(names);
	        gcry_sexp_release(protos);
	        gcry_sexp_release(privs);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
	    }
	    /* Extract the actual name and protocol */
	    token = gcry_sexp_nth_data(names, 1, &tokenlen);
	    if (!token) {
	        gcry_sexp_release(names);
	        gcry_sexp_release(protos);
	        gcry_sexp_release(privs);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
	    }
	    name = malloc(tokenlen + 1);
	    if (!name) {
	        gcry_sexp_release(names);
	        gcry_sexp_release(protos);
	        gcry_sexp_release(privs);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_ENOMEM);
	    }
	    memmove(name, token, tokenlen);
	    name[tokenlen] = '\0';
	    gcry_sexp_release(names);

	    token = gcry_sexp_nth_data(protos, 1, &tokenlen);
	    if (!token) {
	        free(name);
	        gcry_sexp_release(protos);
	        gcry_sexp_release(privs);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
	    }
	    proto = malloc(tokenlen + 1);
	    if (!proto) {
	        free(name);
	        gcry_sexp_release(protos);
	        gcry_sexp_release(privs);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_ENOMEM);
	    }
	    memmove(proto, token, tokenlen);
	    proto[tokenlen] = '\0';
	    gcry_sexp_release(protos);

	    /* Make a new OtrlPrivKey entry */
	    p = malloc(sizeof(*p));
	    if (!p) {
	        free(name);
	        free(proto);
	        gcry_sexp_release(privs);
	        gcry_sexp_release(allkeys);
	        return gcry_error(GPG_ERR_ENOMEM);
	    }

	    /* Fill it in and link it up */
	    p->accountname = name;
	    p->protocol = proto;
	    p->pubkey_type = OTRL_PUBKEY_TYPE_DSA;
	    p->privkey = privs;
	    p->next = us->privkey_root;
	    if (p->next) {
	        p->next->tous = &(p->next);
	    }
	    p->tous = &(us->privkey_root);
	    us->privkey_root = p;
	    err = jsapi_make_pubkey(&(p->pubkey_data), &(p->pubkey_datalen), p->privkey);
	    if (err) {
	        gcry_sexp_release(allkeys);
	        otrl_privkey_forget(p);
	        return gcry_error(GPG_ERR_UNUSABLE_SECKEY);
	    }
    }
    gcry_sexp_release(allkeys);

    /* application should write out userstate to disk */
    return gcry_error(GPG_ERR_NO_ERROR);
}


JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiUserstateImportPrivkey(JNIEnv* env, jobject this, jint userstate, jstring accountname, jstring protocol,
        jint p, jint q, jint g, jint y, jint x){
    JSTR_GET(accountname, GPG_ERR_ENOMEM);
    JSTR_GET(protocol, GPG_ERR_ENOMEM);
    gcry_error_t err = jsapi_userstate_import_privkey(userstate,accountname_str, protocol_str,p,q,g,y,x);
    JSTR_RELEASE(accountname); JSTR_RELEASE(protocol);
    return err;
}

JNIEXPORT jstring JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetProtocol(JNIEnv* env, jobject this, jint ctx){
    return JSTRINGIFY(((ConnContext*)ctx)->protocol);
}
JNIEXPORT jstring JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetUsername(JNIEnv* env, jobject this, jint ctx){
    return JSTRINGIFY(((ConnContext*)ctx)->username);
}
JNIEXPORT jstring JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetAccountname(JNIEnv* env, jobject this, jint ctx){
    return JSTRINGIFY(((ConnContext*)ctx)->accountname);
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetMsgstate(JNIEnv* env, jobject this, jint ctx){
    return ((ConnContext*)ctx)->msgstate;
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetProtocolVersion(JNIEnv* env, jobject this, jint ctx){
    return ((ConnContext*)ctx)->protocol_version;
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetSmProgState(JNIEnv* env, jobject this, jint ctx){
    return ((ConnContext*)ctx)->smstate->sm_prog_state;
}

/*
void jsapi_conncontext_get_active_fingerprint(ConnContext* ctx, char* human){
*/
JNIEXPORT void JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetActiveFingerprint(JNIEnv* env, jobject this, jint ctxp, jint human){
    ConnContext *ctx = (ConnContext*)ctxp;
    ((char*)human)[0]='\0';
    if(ctx->active_fingerprint==NULL) return;
    otrl_privkey_hash_to_human(human, ctx->active_fingerprint->fingerprint);
}

JNIEXPORT jstring JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetTrust(JNIEnv* env, jobject this, jint ctxp){
    ConnContext *ctx = (ConnContext*)ctxp;
    if(ctx->active_fingerprint == NULL) return NULL;
    return JSTRINGIFY(ctx->active_fingerprint->trust);
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetTheirInstance(JNIEnv* env, jobject this, jint ctx){
    return ((ConnContext*)ctx)->their_instance;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetOurInstance(JNIEnv* env, jobject this, jint ctx){
    return ((ConnContext*)ctx)->our_instance;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiConncontextGetMaster(JNIEnv* env, jobject this, jint ctx){
    return ((ConnContext*)ctx)->their_instance;
}
JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiInstagGetTag(JNIEnv* env, jobject this, jint instag){
    return ((OtrlInsTag*)instag)->instag;
}

JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiCanStartSmp(JNIEnv* env, jobject this, jint ctxp){
    ConnContext* ctx = (ConnContext*)ctxp;
    if (ctx->smstate->nextExpected == OTRL_SMP_EXPECT1 ) return 1;
    return 0;
}

//MessageAppOps
OtrlPolicy msgops_callback_policy(void *opdata,ConnContext *context){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_POLICY", "(II)I");
        if(mid != NULL){
            return (*env)->CallStaticIntMethod(env, cls, mid, opdata,context);
        }
    }
}

void msgops_callback_create_privkey(void *opdata, const char *accountname,
        const char *protocol){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_CREATE_PRIVKEY", "(ILjava/lang/String;Ljava/lang/String;)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata, JSTRINGIFY(accountname), JSTRINGIFY(protocol));
        }
    }
}
int msgops_callback_is_logged_in(void *opdata, const char *accountname,
        const char *protocol, const char *recipient){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_IS_LOGGED_IN", "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)I");
        if(mid != NULL){
            return (*env)->CallStaticIntMethod(env, cls, mid, opdata, JSTRINGIFY(accountname), JSTRINGIFY(protocol), JSTRINGIFY(recipient));
        }
    }
}
void msgops_callback_inject_message(void *opdata, const char *accountname,
        const char *protocol, const char *recipient, const char *message){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_INJECT_MESSAGE", "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata, JSTRINGIFY(accountname), JSTRINGIFY(protocol),JSTRINGIFY(recipient),JSTRINGIFY(message));
        }
    }
}

void msgops_callback_update_context_list(void *opdata){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_UPDATE_CONTEXT_LIST", "(I)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata);
        }
    }
}

void msgops_callback_new_fingerprint(void *opdata, OtrlUserState us,
        const char *accountname, const char *protocol,
        const char *username, unsigned char fingerprint[20]){
    char human[45];
    otrl_privkey_hash_to_human(human, fingerprint);
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_NEW_FINGERPRINT", "(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata, us, JSTRINGIFY(accountname), JSTRINGIFY(protocol),JSTRINGIFY(username),JSTRINGIFY(human));
        }
    }
}

void msgops_callback_write_fingerprints(void *opdata){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_WRITE_FINGERPRINTS", "(I)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata);
        }
    }
}

void msgops_callback_gone_secure(void *opdata, ConnContext *context){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_GONE_SECURE", "(II)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
        }
    }
}

void msgops_callback_gone_insecure(void *opdata, ConnContext *context){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_GONE_INSECURE", "(II)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
        }
    }
}

void msgops_callback_still_secure(void *opdata, ConnContext *context, int is_reply){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_STILL_SECURE", "(III)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context,is_reply);
        }
    }
}

int msgops_callback_max_message_size(void *opdata, ConnContext *context){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_MAX_MESSAGE_SIZE", "(II)I");
        if(mid != NULL){
            (*env)->CallStaticIntMethod(env, cls, mid, opdata,context);
        }
    }
}

const char * msgops_callback_account_name(void *opdata, const char *account, const char *protocol){
    return account;
}

void msgops_callback_account_name_free(void *opdata, const char *account_name){
    return;
}

//new ops in libotr4
void msgops_callback_received_symkey(void *opdata, ConnContext *context,
        unsigned int use, const unsigned char *usedata,
        size_t usedatalen, const unsigned char *symkey){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_RECEIVED_SYMKEY", "(IIIIII)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context,use,usedata,usedatalen,symkey);
        }
    }
}

const char * msgops_callback_otr_error_message(void *opdata, ConnContext *context, OtrlErrorCode err_code){
    switch( err_code ){
        case OTRL_ERRCODE_ENCRYPTION_ERROR: return "encryption-error";
        case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE: return "msg-not-in-private";
        case OTRL_ERRCODE_MSG_UNREADABLE: return "msg-unreadble";
        case OTRL_ERRCODE_MSG_MALFORMED: return "msg-malformed";
    }
    return "";
}
void msgops_callback_otr_error_message_free(void *opdata, const char *err_msg){
}
void msgops_callback_handle_smp_event(void *opdata, OtrlSMPEvent smp_event,
        ConnContext *context, unsigned short progress_percent,
        char *question){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls == NULL) return;
    switch(smp_event){
        case OTRL_SMPEVENT_ASK_FOR_SECRET:
            mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_SMP_REQUEST", "(II)V");
             if(mid==NULL)return;
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
            return;
        case OTRL_SMPEVENT_ASK_FOR_ANSWER:
            mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_SMP_REQUEST_Q", "(IILjava/lang/String;)V");
             if(mid==NULL)return;
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context,JSTRINGIFY(question));
            return;
        case OTRL_SMPEVENT_IN_PROGRESS:
            return;
        case OTRL_SMPEVENT_SUCCESS:
            mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_SMP_COMPLETE", "(II)V");
             if(mid==NULL)return;
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
            return;
        case OTRL_SMPEVENT_FAILURE:
            mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_SMP_FAILED", "(II)V");
             if(mid==NULL)return;
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
            return;
        case OTRL_SMPEVENT_CHEATED:
        case OTRL_SMPEVENT_ERROR:
            mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_SMP_ERROR", "(II)V");
             if(mid==NULL)return;
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
            return;
        case OTRL_SMPEVENT_ABORT:
            mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_SMP_ABORTED", "(II)V");
             if(mid==NULL)return;
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,context);
            return;
    }
}

void msgops_callback_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
        ConnContext *context, const char *message,
        gcry_error_t err){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_MSG_EVENT", "(IIILjava/lang/String;I)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,msg_event,context,JSTRINGIFY(message),err);
        }
    }
}

void msgops_callback_create_instag(void *opdata, const char *accountname,
        const char *protocol){
    JNIEnv* env = global_env;
    jmethodID mid;
    jclass cls = (*env)->FindClass(env, OTRMODULE);
    if(cls != NULL){
        mid = (*env)->GetStaticMethodID(env, cls, "OPS_CALLBACK_CREATE_INSTAG", "(ILjava/lang/String;Ljava/lang/String;)V");
        if(mid != NULL){
            (*env)->CallStaticVoidMethod(env, cls, mid, opdata,JSTRINGIFY(accountname),JSTRINGIFY(protocol));
        }
    }
}

/* TODO
void msgops_callback_convert_msg(void *opdata, ConnContext *context,
        OtrlConvertType convert_type, char ** dest, const char *src){  
}

void msgops_callback_convert_free(void *opdata, ConnContext *context, char *dest){   
}

void msgops_callback_timer_control(void *opdata, unsigned int interval){
}  */


JNIEXPORT jint JNICALL
Java_otr_OtrModule_CallJsapiMessageappopsNew(JNIEnv* env, jobject this){
    OtrlMessageAppOps *ops = malloc(sizeof(OtrlMessageAppOps));

    ops->policy = msgops_callback_policy;
    ops->create_privkey = msgops_callback_create_privkey;
    ops->is_logged_in = msgops_callback_is_logged_in;
    ops->inject_message = msgops_callback_inject_message;
    ops->update_context_list = msgops_callback_update_context_list;
    ops->new_fingerprint = msgops_callback_new_fingerprint;
    ops->write_fingerprints = msgops_callback_write_fingerprints;
    ops->gone_secure = msgops_callback_gone_secure;
    ops->gone_insecure = msgops_callback_gone_insecure;
    ops->still_secure = msgops_callback_still_secure;
    ops->max_message_size = msgops_callback_max_message_size;
    ops->account_name_free = msgops_callback_account_name_free;
    ops->account_name = msgops_callback_account_name;

    //new in libotr-4
    ops->received_symkey = msgops_callback_received_symkey;
    ops->otr_error_message = msgops_callback_otr_error_message;
    ops->otr_error_message_free = msgops_callback_otr_error_message_free;
    ops->resent_msg_prefix = NULL;
    ops->resent_msg_prefix_free = NULL;
    ops->handle_smp_event = msgops_callback_handle_smp_event;
    ops->handle_msg_event = msgops_callback_handle_msg_event;
    ops->create_instag = msgops_callback_create_instag;
    ops->convert_msg = NULL;
    ops->convert_free = NULL;
    ops->timer_control = NULL;
    //ops->convert_msg = msgops_callback_convert_msg;
    //ops->convert_free = msgops_callback_convert_free;
    //ops->timer_control = msgops_callback_timer_control; // << important do this one
    return ops;
}
