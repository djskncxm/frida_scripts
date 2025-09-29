
// 寄存器信息变化
function get_diff_regs(context, pre_regs) {
	var diff_regs = {};
	let trace_str = "";
	// console.log(Object.keys(JSON.parse(JSON.stringify(context))));
	for (const [reg_name, reg_value] of Object.entries(JSON.parse(JSON.stringify(context)))) {
		if (reg_name != "pc" && pre_regs[reg_name] !== reg_value) {
			pre_regs[reg_name] = reg_value;
			diff_regs[reg_name] = reg_value;
		}
	}
	for (const [reg_name, reg_value] of Object.entries(diff_regs)) {
		if (reg_value.toString() !== "[object Object]") {
			trace_str += reg_name + ": " + reg_value.toString() + "   ";
		}
	}
	return trace_str
}

function so_trace() {
	let base_addr = Module.findBaseAddress("libCtaApiJni.so")
	let func_addr = base_addr.add(0x6825C)
	var module_hello_jni = Process.findModuleByName("libCtaApiJni.so");
	// so文件起始地址
	var module_start = module_hello_jni.base;
	// so文件结束地址
	var module_end = module_hello_jni.base + module_hello_jni.size; // so文件大小

	var pre_regs = {}
	Interceptor.attach(func_addr, {
		onEnter: function(args) {
			// 进程id
			this.tid = Process.getCurrentThreadId();

			Stalker.follow(this.tid, {
				events: {
					call: false,	// CALL instructions: yes please
					// Other events:
					ret: false,	// RET instructions
					exec: true,	// all instructions: not recommended as it's
					// a lot of data
					block: false,	// block executed: coarse execution trace
					compile: false	// block compiled: useful for coverage
				},
				transform(iterator) {
					let instruction = iterator.next();
					do {
						const startAddress = instruction.address;
						const is_module_code = startAddress.compare(module_start) >= 0 &&
							startAddress.compare(module_end) === -1;
						if (is_module_code) {
							// console.log(startAddress, instruction);
							iterator.putCallout(function(context) {
								var pc = context.pc;
								var module = Process.findModuleByAddress(pc);
								if (module) {
									var diff_regs = get_diff_regs(context, pre_regs);
									if (module.name.indexOf("libCtaApiJni.so") !== -1) {
										console.log(module.base + '==>' + '[' + ptr(pc).sub(module.base) + "]",
											Instruction.parse(ptr(pc)),
											'|', diff_regs);
									}

								}

							});
						}

						iterator.keep();
					} while ((instruction = iterator.next()) !== null);
				}

			});

		}, onLeave: function(retval) {
			// 结束tracce
			Stalker.unfollow(this.tid);

		}
	})
}
