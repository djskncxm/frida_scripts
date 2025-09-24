
// 查看什么so开了什么线程，用于反调试中线程地址打印
function HookClone() {
	var clone = Module.findExportByName('libc.so', 'clone');
	Interceptor.attach(clone, {
		onEnter: function(args) {
			// args[3] 子线程的栈地址。如果这个值为 0，可能意味着没有指定栈地址
			if (args[3] != 0) {
				var addr = args[3].add(96).readPointer()
				var so_name = Process.findModuleByAddress(addr).name;
				var so_base = Module.getBaseAddress(so_name);
				var offset = (addr - so_base);
				console.log("===============>", so_name, addr, offset, offset.toString(16));
			}
		},
		onLeave: function(retval) {

		}
	});
}

// 查看加载了什么so文件，作为过反调试的函数
function hook_dlopen() {
	Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
		{
			onEnter: function(args) {
				this.fileName = args[0].readCString()
				console.log(`dlopen onEnter: ${this.fileName}`)
			}, onLeave: function(retval) {
				console.log(`dlopen onLeave fileName: ${this.fileName}`)
				if (this.fileName != null && this.fileName.indexOf("libmsaoaidsec.so") >= 0) {
					let JNI_OnLoad = Module.getExportByName(this.fileName, 'JNI_OnLoad')
					console.log(`dlopen onLeave JNI_OnLoad: ${JNI_OnLoad}`)
				}
			}
		}
	);
}

// 过反调试最简单的用法，把前面clone输出的线程地址直接制空达到无法检测效果，适合后续继续分析
function hook_dlopen2(so_name) {
	Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
		onEnter: function(args) {
			var pathptr = args[0];
			if (pathptr !== undefined && pathptr != null) {
				var path = ptr(pathptr).readCString();
				if (path.indexOf(so_name) !== -1) {
					console.log(path)
					this.match = true
				}
			}
		},
		onLeave: function(retval) {
			if (this.match) {
				console.log(so_name, "加载成功");
				var base = Module.findBaseAddress("libDexHelper.so")
				patch_func_nop(base.add(320504));
				patch_func_nop(base.add(307252));
				patch_func_nop(base.add(348692));
				patch_func_nop(base.add(331640));
				patch_func_nop(base.add(371144));
				patch_func_nop(base.add(324260));
			}
		}
	});
}
function patch_func_nop(addr) {
	Memory.patchCode(addr, 8, function(code) {
		code.writeByteArray([0xE0, 0x03, 0x00, 0xAA]);
		code.writeByteArray([0xC0, 0x03, 0x5F, 0xD6]);
		console.log("patch code at " + addr)
	});
}
// ----------------------------------------------------------
// hook_dlopen("libDexHelper.so")
setImmediate(hook_dlopen)
// ----------------------------------------------------------
