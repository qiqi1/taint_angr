import idc
import idautils
import idaapi
import sys
import os
import re
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *


class Form(idaapi.PluginForm):
    def __init__(self):
        super(Form, self).__init__()
        #
        self.browser = None
        #
        self.data = None
        self.curr_line = 0
        #
        self.base_addr = None
        self.addr0 = None
        self.addr1 = None
        self.addr2 = None
        self.addr3 = None
        #
        self.addr_list = None
        self.module_base = None
        #
        self.addr_is_load = False
        
        # 
        self.or_ins = 0
        self.cur_ins = 0
        
    
    # callback when the "Load" button is clicked
    def _load_file(self):
        #
        self.data = None
        
        options = QtWidgets.QFileDialog.Options()
        default_filename = os.path.join(os.path.dirname(__file__),
                                        'init.ini')
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.parent, "Choose configuration file", default_filename,
            "Configuration files (*.txt)", options=options)
        if not filename or not os.path.exists(filename):
            return
        
        with open(filename,'rb') as f:
            self.data = f.readlines()
        
        self.browser.append(filename+' load already')
        
    

    #------ IMark(0x4210e8, 2, 1) ------
    def _get_curr_base(self,one_ir):
        tmpvalues =  re.findall('[(](.*?)[)]',one_ir)[0].split(',')
        cur_base = int(tmpvalues[0],16)
        return cur_base
    
    #step into
    def _step_into(self):
        #
        if self.data == None:
            self.browser.append("please load file before")
            return
        
        #
        if not self.addr_is_load:
            self.browser.append("please load base addr before")
            return
        
        #
        ir_list = []
        mark_num = 0
        min_dist = 0xffffffff
        for i in range(self.curr_line,len(self.data)):
            one_ir = self.data[i]
            if 'IMark' in one_ir:
                if mark_num >= 1:
                    self.curr_line = i
                    break
                else:
                    ir_list.append(one_ir)
                    cur_addr = self._get_curr_base(one_ir) - self.module_base
                    self.or_ins = self.cur_ins
                    self.cur_ins = cur_addr
                    
                    if self.or_ins != 0:
                        idc.SetColor(self.or_ins, CIC_ITEM, 0xFFFFFFFF)    
                    
                mark_num = mark_num + 1
            else:
                if 'func_' in one_ir:
                    if min_dist == 0xffffffff:
                        ref_addr = self.cur_ins
                        for addr in idautils.CodeRefsTo(ref_addr,1):
                            if abs(addr-self.or_ins) <= min_dist:
                                min_dist = abs(addr-self.or_ins)
                                self.cur_ins = addr
                ir_list.append(one_ir)
        
        idc.jumpto(self.cur_ins)
        idc.SetColor(self.cur_ins, CIC_ITEM, 0x2020c0)
        for one_ir in ir_list:
            self.browser.append(one_ir)
    
    #run
    def _run(self):
        if self.data == None:
            self.browser.append("please load file before")
            return
        
        if not self.addr_is_load:
            self.browser.append("please load base addr before")
            return
        
        if len(self.addr_list) == 0:
            self.browser.append("please bp addr")
            return
        
        #
        ir_list = []
        mark_num = 0
        for i in range(self.curr_line,len(self.data)):
            one_ir = self.data[i]
            if 'IMark' in one_ir:
                if mark_num >= 1:
                    self.curr_line = i
                    break
                #
                cur_addr = self._get_curr_base(one_ir) - self.module_base
                for bp_addr in self.addr_list:
                    if bp_addr == cur_addr:
                        idc.jumpto(cur_addr)
                        idc.SetColor(cur_addr, CIC_ITEM, 0x2020c0)
                        self.or_ins = self.cur_ins
                        self.cur_ins = cur_addr
                        ir_list.append(one_ir)
                        mark_num = mark_num + 1
                        break
            else:
                if mark_num >= 1:
                    ir_list.append(one_ir)
        
        if mark_num == 0:
            self.browser.append('bp address is not taint')
        else:
            for one_ir in ir_list:
                self.browser.append(one_ir)
                
    
    #_load_addr
    def _load_addr(self):
        if self.cur_ins != 0:
            idc.SetColor(self.cur_ins, CIC_ITEM, 0xFFFFFFFF)
    
        self.addr_list = []
        addr_0 = self.addr0.text()
        addr_1 = self.addr1.text()
        addr_2 = self.addr2.text()
        addr_3 = self.addr3.text()
        
        base = self.base_addr.text()
        if base != '':
            self.module_base = int(base,16)
            self.addr_is_load = True
        else:
            self.browser.append("base can't null")
            return
        
        
        if addr_0 != '':
            self.addr_list.append(int(addr_0,16))
        if addr_1 != '':
            self.addr_list.append(int(addr_1,16))
        if addr_1 != '':
            self.addr_list.append(int(addr_1,16))
        if addr_1 != '':
            self.addr_list.append(int(addr_1,16))
        
        self.browser.append("load base already")
        
    
        
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        
        layout = QGridLayout(self.parent)
        self.browser = QTextBrowser(self.parent)
        
        #self.browser.append('ir trace')
        
        layout.addWidget(self.browser, 0, 0)
        
        addr_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(addr_split, 1, 0)
        
        #
        lbl_base_addr = QtWidgets.QLabel("base:")
        self.base_addr = QtWidgets.QLineEdit(self.parent)
        self.base_addr.setAlignment(Qt.AlignLeft)
        
        
        lbl_addr0 = QtWidgets.QLabel("bp addr1:")
        self.addr0 = QtWidgets.QLineEdit(self.parent)
        self.addr0.setAlignment(Qt.AlignLeft)
        lbl_addr1 = QtWidgets.QLabel("bp addr2:")
        self.addr1 = QtWidgets.QLineEdit(self.parent)
        self.addr1.setAlignment(Qt.AlignLeft)
        lbl_addr2 = QtWidgets.QLabel("bp addr3:")
        self.addr2 = QtWidgets.QLineEdit(self.parent)
        self.addr2.setAlignment(Qt.AlignLeft)
        lbl_addr3 = QtWidgets.QLabel("bp addr4:")
        self.addr3 = QtWidgets.QLineEdit(self.parent)
        self.addr3.setAlignment(Qt.AlignLeft)
        #button
        self.load_addr = QtWidgets.QPushButton('LoadAddr')
        self.load_addr.clicked.connect(self._load_addr)
        addr_split.addWidget(self.load_addr)
        
        addr_split.addWidget(lbl_base_addr)
        addr_split.addWidget(self.base_addr)
        addr_split.addWidget(lbl_addr0)
        addr_split.addWidget(self.addr0)
        addr_split.addWidget(lbl_addr1)
        addr_split.addWidget(self.addr1)
        addr_split.addWidget(lbl_addr2)
        addr_split.addWidget(self.addr2)
        addr_split.addWidget(lbl_addr3)
        addr_split.addWidget(self.addr3)
        
        button_split = QtWidgets.QSplitter(self.parent)
        layout.addWidget(button_split, 2, 0)
        #button
        self.simple_runin = QtWidgets.QPushButton('step')
        self.simple_runin.clicked.connect(self._step_into)
        button_split.addWidget(self.simple_runin)
        
        
        self.simple_run = QtWidgets.QPushButton('run')
        self.simple_run.clicked.connect(self._run)
        button_split.addWidget(self.simple_run)
        
        self.load_file = QtWidgets.QPushButton('LoadFile')
        self.load_file.clicked.connect(self._load_file)
        button_split.addWidget(self.load_file)

        #layout.setRowStretch(1, 0)
        self.parent.setLayout(layout)
        
        
    def show(self):
        return idaapi.PluginForm.Show(
            self, "idataint",
            options=(idaapi.PluginForm.FORM_PERSIST |
                     idaapi.PluginForm.FORM_SAVE |
                     idaapi.PluginForm.FORM_MENU |
                     idaapi.PluginForm.FORM_RESTORE |
                     idaapi.PluginForm.FORM_TAB))
            
            
class myIdaPlugin(idaapi.plugin_t):
    flags=0
    wanted_name="taint debug"
    wanted_hotkey="Alt+c"
    comment="taint debug plugin"
    help="Something helpful"
    
    def init(self):
        return idaapi.PLUGIN_KEEP
        
    def term(self):
        pass
        
    def run(self,arg):
        form = Form()
        form.show()
        
def PLUGIN_ENTRY():
    return myIdaPlugin()




            








