import frida, sys

rdev = frida.get_usb_device()


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


js_code = """
Java.perform(
    function () {
        var Address = Module.findBaseAddress("libtensorflowlite_c.so");
        console.log("地址："+Address);
        // IDA反编译os函数名：Java_com_sdfglb_forjack_NativeLib_forJackMore
        var native = Module.getExportByName("libtensorflowlite_c.so",
                        "TfLiteModelCreate");
        Interceptor.attach(native,{
            onEnter: function (args) {
                i += 1;
                console.log(i);
                console.log("Enter: " + new NativePointer(args[0]));
                console.log("Enter: " + new NativePointer(args[1]).toInt32());
                dump_memory(new NativePointer(args[0]),new NativePointer(args[1]).toInt32(),i)
                    
                // console.log("Enter start");
                // console.log("Enter" + args[0]);
                // console.log("Enter" + ptr(args[1]).readU32());
                console.log("Enter over");
                // console.log(args[2].toInt64());
                // console.log(args[3].toInt64());
                // console.log(args[4]);
                // console.log(args[5]);
                // console.log(args[6]);
                // console.log(args[7]);
            },
            onLeave:function (result) {
                console.log(result);
                console.log("Leave over");
            }

        })
    }
);
function dump_memory(base,size,i) {
    var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
    var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
    var dir = "/sdcard/Android/data/" + package + "/files"
    var file_path = dir + "/dumpmemory_"+ i +".tflite";
    var file_handle = new File(file_path, "wb");
    console.log(file_path);
    if (file_handle && file_handle != null) {
        Memory.protect(base,size, 'rwx');
        var libso_buffer = base.readByteArray(size);
        file_handle.write(libso_buffer);
        file_handle.flush();
        file_handle.close();
        console.log("[dump]:", file_path);
    }
}
var package = "your pacakge" // Please replace this with your hook App package name, such as com.tencent.wechat.
var i = 0;
"""

process = rdev.enumerate_processes()
print(process)
session = rdev.attach("xxxx")  # Specified APP name, it can be Chinese.
script = session.create_script(js_code)
# script.on('message', on_message)
print('[*] Running')
script.load()
sys.stdin.read()
