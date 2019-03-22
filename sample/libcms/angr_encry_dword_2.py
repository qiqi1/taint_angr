# -*- coding: UTF-8 -*-
import angr
import claripy

#加载二进制文件
proj = angr.Project('C:\\Users\\Administrator\\Desktop\\angr_ana\\libcms\\libcms.so')
#设置程序运行开始地址
state = proj.factory.blank_state(addr=proj.entry+0x21B98+1)

#设置寄存器值
state.regs.r0 = 0x11223344


#初始化一个执行引擎
simgr = proj.factory.simgr(state)

while len(simgr.active) == 1:
    #执行
    simgr.step()
    #设置执行停止条件
    if simgr.active[0].addr >= proj.entry+0x21D56+0x01:
        break




#设置污点源,下面的对应的是污点寄存器是r0
taint_value = ['offset=8']
taint_mem = []
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



