# -*- coding: UTF-8 -*-

import angr
import claripy



proj = angr.Project('C:\\Users\\Administrator\\Desktop\\angr_ana\\tmp\\tmp')

state = proj.factory.blank_state(addr=0x804853d)
mem = 0x10000000
state.memory.store(0x10000004,state.solver.BVV('1122334455667788\x00',136))
state.memory.store(0x10000000,state.solver.BVV(0x10000004,32),endness=angr.archinfo.Endness.LE)
state.regs.esp = 0xffffffc


simgr = proj.factory.simgr(state)

while len(simgr.active) == 1:
    simgr.step()
    try:
        if simgr.active[0].addr == 0x8048601:
            #print("0x%x"%simgr.active[0].addr)
            #ret = simgr.active[0].mem[simgr.active[0].regs.r3].long.concrete
            break
    except:
        break
    


##输出所有的ir语句
# for cfg_ir in simgr.ir_trace:
    # for addr_ir in cfg_ir:
        # print(addr_ir)

#设置污点源,下面的对应的是污点寄存器是r0
taint_value = []
taint_mem = []

for i in range(16):
    taint_mem.append(0x10000004+i)

#初始化污点分析引擎
taint_handle = angr.StaticTaint.TaintHandle(simgr.ir_trace)
#进行污点分析
taint_handle.taint(taint_value,taint_mem)

#输出污点分析数据
for i in range(len(taint_handle.IMark_list)):
    if len(taint_handle.IMark_list[i]) != 0:
        for key in taint_handle.IMark_list[i]:
            print('------ '+key+' ------')
            for j in range(len(taint_handle.IMark_list[i][key])):
                print(taint_handle.IMark_list[i][key][j])
