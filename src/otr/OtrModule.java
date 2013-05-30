package otr;

import org.appcelerator.kroll.KrollModule;
import org.appcelerator.kroll.annotations.Kroll;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.kroll.*;
import org.appcelerator.kroll.common.Log;

@Kroll.module(name="OtrModule", id="tiotrmodule")
public class OtrModule extends KrollModule
{
	static
    {
        System.loadLibrary("otrjni");
    }

    private static KrollFunction ops_callback_function;
    private static KrollObject ops_callback_scope;

	public OtrModule()
	{
		super();
		initialize();
	}

	@Kroll.onAppCreate
	public static void onAppCreate(TiApplication app)
	{
	}

	private native void initialize();
    private native void shutdown();

    //assign javascript callback function called from OPS_CALLBACK_x methods
    @Kroll.method
    public void setup_ops_callback(Object objFunction){
        ops_callback_function = (KrollFunction)objFunction;
        ops_callback_scope = getKrollObject();
    }

    //OPS_CALLBACKS_x - called from C through JNI
    protected static int  OPS_CALLBACK_POLICY(int a,int b){
        return ((Integer)ops_callback_function.call(ops_callback_scope, new Object[]{"policy",a,b})).intValue();
    }
    protected static void OPS_CALLBACK_CREATE_PRIVKEY(int a, String b, String c){
        ops_callback_function.call(ops_callback_scope, new Object[]{"create_privkey",a,b,c});
    }
    protected static int  OPS_CALLBACK_IS_LOGGED_IN(int a, String b, String c, String d){
        return ((Integer)ops_callback_function.call(ops_callback_scope, new Object[]{"is_logged_in",a,b,c,d})).intValue();
    }
    protected static void OPS_CALLBACK_INJECT_MESSAGE(int a, String b,String c,String d,String e){
        ops_callback_function.call(ops_callback_scope, new Object[]{"inject_message",a,b,c,d,e});
    }
    protected static void OPS_CALLBACK_UPDATE_CONTEXT_LIST(int a){
        ops_callback_function.call(ops_callback_scope, new Object[]{"update_context_list",a});
    }
    protected static void OPS_CALLBACK_NEW_FINGERPRINT(int a, int b, String c, String d, String e, String f){
        ops_callback_function.call(ops_callback_scope, new Object[]{"new_fingerprint",a,b,c,d,e,f});
    }
    protected static void OPS_CALLBACK_WRITE_FINGERPRINTS(int a){
        ops_callback_function.call(ops_callback_scope, new Object[]{"write_fingerprints",a});
    }
    protected static void OPS_CALLBACK_GONE_SECURE(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"gone_secure",a,b});
    }
    protected static void OPS_CALLBACK_GONE_INSECURE(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"gone_insecure",a,b});
    }
    protected static void OPS_CALLBACK_STILL_SECURE(int a, int b, int c){
        ops_callback_function.call(ops_callback_scope, new Object[]{"still_secure",a,b,c});
    }
    protected static int  OPS_CALLBACK_MAX_MESSAGE_SIZE(int a, int b){
        return ((Integer)ops_callback_function.call(ops_callback_scope, new Object[]{"max_message_size",a,b})).intValue();
    }
    protected static void OPS_CALLBACK_RECEIVED_SYMKEY(int a, int b,int c,int d,int e,int f){
        ops_callback_function.call(ops_callback_scope, new Object[]{"received_symkey",a,b,c,d,e,f});
    }
    protected static void OPS_CALLBACK_SMP_REQUEST(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"smp_request",a,b});
    }
    protected static void OPS_CALLBACK_SMP_REQUEST_Q(int a, int b, String c){
        ops_callback_function.call(ops_callback_scope, new Object[]{"smp_request",a,b,c});
    }
    protected static void OPS_CALLBACK_SMP_COMPLETE(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"smp_complete",a,b});
    }
    protected static void OPS_CALLBACK_SMP_FAILED(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"smp_failed",a,b});
    }
    protected static void OPS_CALLBACK_SMP_ERROR(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"smp_error",a,b});
    }
    protected static void OPS_CALLBACK_SMP_ABORTED(int a, int b){
        ops_callback_function.call(ops_callback_scope, new Object[]{"smp_aborted",a,b});
    }
    protected static void OPS_CALLBACK_MSG_EVENT(int a, int b, int c, String d, int e){
        ops_callback_function.call(ops_callback_scope, new Object[]{"msg_event",a,b,c,d,e});
    }
    protected static void OPS_CALLBACK_CREATE_INSTAG(int a, String b, String c){
        ops_callback_function.call(ops_callback_scope, new Object[]{"create_instag",a,b,c});
    }

    //low-level memory access functions.. TODO: Get rid of these!
    @Kroll.method public native int  CallMalloc(int n);
    @Kroll.method public native void CallFree(int ptr);
    @Kroll.method public void DoSetValueInt32(int ptr, Object value){

        int i32 = 0;
        double d32 =0;
        if( value != null){
            i32 = ((Number)value).intValue();
            d32 = ((Number)value).doubleValue();
        }
        if(d32 > 2147483647){
            //Log.d("OTRMODULE","d32 > 2147483646 ===");
            i32 = (int)(d32 - 2147483647);
            i32 = i32 |0x80000000;
        }else if( d32 < -2147483647){
            //Log.d("OTRMODULE","d32 < 2147483646 ===");
            i32 = (int)(d32 + 2147483647)+1;
            i32 = i32 |0x80000000;
        }
        CallSetValueInt32(ptr, i32);
    }
    @Kroll.method public native void CallSetValueInt32(int ptr,int value);
    @Kroll.method public void DoSetValueInt16(int ptr, Object value){
        CallSetValueInt16(ptr, ((Number)value).shortValue());
    }
    @Kroll.method public native void CallSetValueInt16(int ptr,short value);
    @Kroll.method public void DoSetValueInt8(int ptr, Object value){
        CallSetValueInt8(ptr, ((Number)value).byteValue());
    }
    private native void CallSetValueInt8(int ptr,byte value);
    @Kroll.method public native int CallGetValueInt32(int ptr);
    @Kroll.method public native short CallGetValueInt16(int ptr);
    @Kroll.method public int DoGetValueInt8(int ptr){
        int v = CallGetValueInt8(ptr);
        if(v > 127) v = -256 + v;
        return v;
    }
    public native int CallGetValueInt8(int ptr);

    //stringify
    @Kroll.method public native String CallStringify(int ptr);

    //libgcrypt functions..
    @Kroll.method public native String CallGcryStrerror(int err);

    @Kroll.method public native int  CallGcryMpiNew(int n);
    @Kroll.method public native int  CallGcryMpiSet(int mpi_a, int mpi_b);
    @Kroll.method public native void CallGcryMpiRelease(int mpi_a);
    @Kroll.method public native int  CallGcryMpiScan(int a, int b, String c, int d, int e);
    @Kroll.method public native int  CallGcryMpiPrint(int a, int b, int c, int d, int e);

    //libotr functions
    @Kroll.method public native String CallOtrlVersion();
    @Kroll.method public native int CallOtrlUserstateCreate();
    @Kroll.method public native void CallOtrlUserstateFree(int ptr);
    @Kroll.method public native int CallOtrlPrivkeyRead(int us, String filename);
    @Kroll.method public native int CallOtrlPrivkeyFingerprint(int us,int fp,String username,String protocol);
    @Kroll.method public native int CallOtrlPrivkeyGenerate(int us,String filename,String username, String protocol);
    @Kroll.method public native int CallOtrlPrivkeyReadFingerprints(int us,String filename,int add_app_data,int data);
    @Kroll.method public native int CallOtrlPrivkeyWriteFingerprints(int us,String filename);
    @Kroll.method public native void CallOtrlPrivkeyForget(int ptr);
    @Kroll.method public native void CallOtrlPrivkeyForgetAll(int ptr);
    @Kroll.method public native int CallOtrlPrivkeyFind(int us,String username, String protocol);
    @Kroll.method public native int CallOtrlContextFind(int userstate, String user, String username, 
    		String protocol, int their_instance, int add_if_missing, int addedp, int add_appdata, int data );
    @Kroll.method public native int CallOtrlMessageSending(int userstate,
            int ops, int opdata, String accountname, String protocol,
            String recipient, int instag, String original_msg,
            int tlvs, int messagep, int fragPolicy, int contextp,
            int add_appdata, int data);
    @Kroll.method public native int CallOtrlMessageReceiving(int userstate,
            int ops, int opdata, String accountname, String protocol,
            String sender, String message, int newmessagep,
            int tlvsp, int contextp,
            int add_appdata, int data);
    @Kroll.method public native void CallOtrlMessageFree(int ptr);
    @Kroll.method public native void CallOtrlMessageDisconnect(int userstate,
            int ops, int opdata, String accountname, String protocol,
            String username, int instance);
    @Kroll.method public native void CallOtrlMessageDisconnectAllInstances(int userstate,
            int ops, int opdata, String accountname, String protocol,
            String username);
    @Kroll.method public native void CallOtrlMessageInitiateSmp(int userstate,
            int ops, int opdata, int context, String secret, int secretlen);
    @Kroll.method public native void CallOtrlMessageInitiateSmpQ(int userstate,
            int ops, int opdata, int context, String question, String secret, int secretlen);
    @Kroll.method public native void CallOtrlMessageRespondSmp(int userstate,
            int ops, int opdata, int context, String secret, int secretlen);
    @Kroll.method public native void CallOtrlMessageAbortSmp(int userstate,
            int ops, int opdata, int context);
    @Kroll.method public native int CallOtrlMessageSymkey(int userstate,
            int ops, int opdata, int context, int use, int usedata, int usedatalen, int symkey);
    @Kroll.method public native int  CallOtrlMessagePollGetDefaultInterval(int userstate);
    @Kroll.method public native void CallOtrlMessagePoll(int userstate, int ops, int opdata);
    @Kroll.method public native int CallOtrlInstagFind(int userstate,
            String accountname, String protocol);
    @Kroll.method public native int CallOtrlInstagRead(int userstate,
            String filename);
    @Kroll.method public native int CallOtrlInstagWrite(int userstate,
            String filename);
    @Kroll.method public native int CallOtrlInstagGenerate(int userstate, String filename,
            String accountname, String protocol);
    @Kroll.method public native void CallOtrlTlvFree(int tlv);
    @Kroll.method public native int CallOtrlTlvFind(int tlvs, int type);

    //JSAPI Helper functions
    @Kroll.method public native int CallJsapiUserstateGetPrivkeyRoot(int us);
    @Kroll.method public native int CallJsapiUserstateGetPrivkeyNext(int p);
    @Kroll.method public native int CallJsapiUserstateGetPrivkeyAccountname(int p);
    @Kroll.method public native String CallJsapiPrivkeyGetProtocol(int p);
    @Kroll.method public native int CallJsapiPrivkeyWriteTrustedFingerprints(int userstate, String filename);
    @Kroll.method public native int CallJsapiUserstateWriteToFile(int userstate, String filename);
    @Kroll.method public native int CallJsapiPrivkeyDelete(int userstate, String filename,
            String accountname, String protocol);
    @Kroll.method public native int CallJsapiPrivkeyGetDsaToken(int keyToExportPtr, String token,
                int buffer, int buflen, int nbytes);
    @Kroll.method public native int CallJsapiUserstateImportPrivkey(int userstate, String accountname, String protocol,
            int p, int q, int g, int y, int x);
    @Kroll.method public native String CallJsapiConncontextGetProtocol(int ctx);
    @Kroll.method public native String CallJsapiConncontextGetUsername(int ctx);
    @Kroll.method public native String CallJsapiConncontextGetAccountname(int ctx);
    @Kroll.method public native int CallJsapiConncontextGetMsgstate(int ctx);
    @Kroll.method public native int CallJsapiConncontextGetProtocolVersion(int ctx);
    @Kroll.method public native int CallJsapiConncontextGetSmProgState(int ctx);
    @Kroll.method public native void CallJsapiConncontextGetActiveFingerprint(int ctxp, int human);
    @Kroll.method public native String CallJsapiConncontextGetTrust(int ctxp);
    @Kroll.method public native int CallJsapiConncontextGetTheirInstance(int ctx);
    @Kroll.method public native int CallJsapiConncontextGetOurInstance(int ctx);
    @Kroll.method public native int CallJsapiConncontextGetMaster(int ctx);
    @Kroll.method public native int CallJsapiInstagGetTag(int instag);
    @Kroll.method public native int CallJsapiCanStartSmp(int ctxp);
    @Kroll.method public native int CallJsapiMessageappopsNew();
}
