/**
 * hook RegisterNatives 过滤 soName
 * @param soName so名称
 * @param classNameList native类名 可为空,需要完整路径  包名+类名
 */
function hook_RegisterNatives(soName, classNameList = []) {
	var module = Process.findModuleByName("libart.so");
	console.log("moudle", module);
	if (module != null) {
		var symbols = module.enumerateSymbols();
		// 存储所有符合条件的 RegisterNatives 地址
		var registerNativesAddrs = [];

		// 遍历符号表，收集所有目标地址
		for (var i = 0; i < symbols.length; i++) {
			var symbol = symbols[i].name;
			if ((symbol.indexOf("CheckJNI") == -1) && (symbol.indexOf("JNI") >= 0) && (symbol.indexOf("RegisterNatives") >= 0)) {
				registerNativesAddrs.push(symbols[i].address);
				// console.log("RegisterNatives_addr: ", JSON.stringify(symbols[i]));
				console.log("RegisterNatives_addr: ", symbols[i].address);
			}
		}

		// 对每个地址分别 Hook，复用原有解析逻辑
		registerNativesAddrs.forEach(function (addr) {
			Interceptor.attach(addr, {
				onEnter: function (args) {
					var env = args[0];
					var jclass = args[1];
					var class_name = Java.vm.tryGetEnv().getClassName(jclass);
					var methods_ptr = ptr(args[2]);
					var method_count = args[3].toInt32();

					if (classNameList.length == 0) {
						console.log("RegisterNatives method counts: ", method_count);
						for (var i = 0; i < method_count; i++) {
							var name = methods_ptr.add(i * Process.pointerSize * 3).readPointer().readCString();
							var sig = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer().readCString();	
							var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
							var find_module = Process.findModuleByAddress(fnPtr_ptr);
							if (find_module != null && soName != null && find_module.name.indexOf(soName) != -1) {
								console.log("RegisterNatives java_class: ", class_name, "name: ", name, "sig: ", sig, "fnPtr: ", fnPtr_ptr, "module_name: ", find_module.name, "module_base: ", find_module.base, "offset: ", ptr(fnPtr_ptr).sub(find_module.base));
							} else {
								console.log("RegisterNatives java_class: ", class_name, "name: ", name, "sig: ", sig, "fnPtr: ", fnPtr_ptr, "module_name: ", find_module.name, "module_base: ", find_module.base, "offset: ", ptr(fnPtr_ptr).sub(find_module.base));
							}
						}
					} else {
						if (classNameList.includes(class_name)) {
							console.log("RegisterNatives method counts: ", method_count);
							for (var i = 0; i < method_count; i++) {
								var name = methods_ptr.add(i * Process.pointerSize * 3).readPointer().readCString();
								var sig = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize).readPointer().readCString();
								var fnPtr_ptr = methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2).readPointer();
								var find_module = Process.findModuleByAddress(fnPtr_ptr);
								if (find_module != null && soName != null && find_module.name.indexOf(soName) != -1) {
									console.log("RegisterNatives java_class: ", class_name, "name: ", name, "sig: ", sig, "fnPtr: ", fnPtr_ptr, "module_name: ", find_module.name, "module_base: ", find_module.base, "offset: ", ptr(fnPtr_ptr).sub(find_module.base));
								} else {
									console.log("RegisterNatives java_class: ", class_name, "name: ", name, "sig: ", sig, "fnPtr: ", fnPtr_ptr, "module_name: ", find_module.name, "module_base: ", find_module.base, "offset: ", ptr(fnPtr_ptr).sub(find_module.base));
								}
							}
						}
					}
				},
				onLeave: function (retval) {}
			});
		});
		console.log("已 Hook " + registerNativesAddrs.length + " 个 RegisterNatives 实例");
	}
}

hook_RegisterNatives("libhbsecurity.so", ["com.max.security.SecurityTool"]);
