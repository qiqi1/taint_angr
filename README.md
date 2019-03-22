# taint-angr-ida-plugin
一个基于angr修改的ida污点分析插件  
本插件支持ida 7.0+版本  

# window安装过程
1、下载文件  
https://gitlab.stnts.com/VA/angr  
2、安装python3版本  
3、安装python库  
pip3 install cle  
pip3 install claripy  
4、编译  
在vs的命令行下执行下列命令：  
python setup.py build  
python setup.py install



# 版本修复说明
v0.2修复了libc库部分函数ir缺失，导致污点跟踪中断的问题


