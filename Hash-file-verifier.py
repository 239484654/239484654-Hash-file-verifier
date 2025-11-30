import os
import sys
import wx
import hashlib
import zlib
import sqlite3
import threading
import ctypes
import ctypes.wintypes
from ctypes import windll, byref, cast, POINTER
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import logging
import os
import time

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 常量定义
SE_RESTORE_NAME = "SeRestorePrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
TOKEN_READ = 0x20008
OWNER_SECURITY_INFORMATION = 0x00000001
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
MAX_RETRY_COUNT = 3
BATCH_SIZE = 100  # 增加批处理大小以提高效率
BUFFER_SIZE = 1048576  # 增加缓冲区大小到1MB

# Windows API绑定
kernel32 = windll.kernel32
advapi32 = windll.advapi32

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", ctypes.wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

PSID = ctypes.c_void_p
SECURITY_INFORMATION = ctypes.wintypes.DWORD

# API函数类型定义
OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.HANDLE)]
OpenProcessToken.restype = ctypes.wintypes.BOOL

LookupPrivilegeValue = advapi32.LookupPrivilegeValueW
LookupPrivilegeValue.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.POINTER(LUID)]
LookupPrivilegeValue.restype = ctypes.wintypes.BOOL

AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(ctypes.wintypes.DWORD)]
AdjustTokenPrivileges.restype = ctypes.wintypes.BOOL

SetNamedSecurityInfo = advapi32.SetNamedSecurityInfoW
SetNamedSecurityInfo.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, SECURITY_INFORMATION, PSID, PSID, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.POINTER(ctypes.wintypes.DWORD)]
SetNamedSecurityInfo.restype = ctypes.wintypes.DWORD

# 核心工具类与函数
class AtomicCounter:
    """线程安全的原子计数器，用于进度更新"""
    def __init__(self, initial=0):
        self._value = initial
        self._lock = threading.Lock()
    
    def increment(self, amount=1):
        with self._lock:
            self._value += amount
            return self._value
    
    @property
    def value(self):
        with self._lock:
            return self._value

# 权限相关函数优化
def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"权限检查失败: {e}")
        return False

def run_as_admin():
    """以管理员权限重启程序"""
    try:
        return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) > 32
    except Exception as e:
        logger.error(f"提权失败: {e}")
        return False

def enable_privilege(privilege_name):
    """启用系统特权，优化版"""
    token_handle = ctypes.wintypes.HANDLE()
    try:
        if not OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, byref(token_handle)):
            logger.error(f"无法打开进程令牌: {ctypes.GetLastError()}")
            return False
        
        luid = LUID()
        if not LookupPrivilegeValue(None, privilege_name, byref(luid)):
            logger.error(f"无法获取特权LUID: {ctypes.GetLastError()}")
            return False
        
        token_privileges = TOKEN_PRIVILEGES()
        token_privileges.PrivilegeCount = 1
        token_privileges.Privileges[0].Luid = luid
        token_privileges.Privileges[0].Attributes = 0x00000002  # SE_PRIVILEGE_ENABLED
        
        result = AdjustTokenPrivileges(token_handle, False, byref(token_privileges), 0, None, None)
        return result and ctypes.GetLastError() == 0  # 确保特权设置成功
    except Exception as e:
        logger.error(f"启用特权失败: {e}")
        return False
    finally:
        if token_handle.value != 0:
            kernel32.CloseHandle(token_handle)

def take_ownership(file_path):
    """获取文件所有权，优化版"""
    try:
        if not enable_privilege(SE_RESTORE_NAME):
            logger.error("无法启用SE_RESTORE_NAME特权")
            return False
        
        current_user = ctypes.create_unicode_buffer(256)
        size = ctypes.c_uint(256)
        if not advapi32.GetUserNameExW(3, current_user, byref(size)):
            logger.error(f"获取当前用户SID失败: {ctypes.GetLastError()}")
            return False
        
        sid_use = ctypes.wintypes.DWORD()
        if not advapi32.LookupAccountNameW(None, current_user, None, byref(size), None, None, byref(sid_use)) and ctypes.GetLastError() != 122:
            logger.error(f"转换SID失败: {ctypes.GetLastError()}")
            return False
        
        sid_buffer = ctypes.create_string_buffer(size.value)
        sid = cast(sid_buffer, PSID)
        domain = ctypes.create_unicode_buffer(256)
        domain_size = ctypes.c_uint(256)
        
        if not advapi32.LookupAccountNameW(None, current_user, sid, byref(size), domain, byref(domain_size), byref(sid_use)):
            logger.error(f"转换SID失败: {ctypes.GetLastError()}")
            return False
        
        return SetNamedSecurityInfo(file_path, 1, OWNER_SECURITY_INFORMATION, sid, None, None, None) == 0
    except Exception as e:
        logger.error(f"获取所有权失败: {e}")
        return False

# 哈希计算与文件处理
def normalize_path(path, auto_parse=True):
    """处理Windows长路径，包括UNC路径"""
    # 安全检查：防止路径遍历攻击
    if not path or not isinstance(path, str):
        return None
        
    # 处理环境变量（如果需要）
    processed_path = os.path.expandvars(path) if auto_parse else path
    
    # 处理UNC路径
    if processed_path.startswith('\\\\') and not processed_path.startswith('\\\\?\\'):
        # UNC路径格式：\\server\share -> \\?\UNC\server\share
        return f'\\\\?\\UNC\\{processed_path[2:]}'
    
    # 处理长路径前缀
    if not processed_path.startswith('\\\\?\\'):
        # 转换为绝对路径（确保前缀有效性）
        abs_path = os.path.abspath(processed_path)
        # 添加长路径前缀
        return f'\\\\?\\{abs_path}'
    
    return processed_path

def process_file(file_path, algorithms, auto_parse=False):
    """处理单个文件的哈希计算，优化版"""
    # 规范化路径
    file_path_norm = normalize_path(file_path, auto_parse)
    if not file_path_norm:
        return False, "路径规范化失败"
        
    # 路径验证
    if not os.path.exists(file_path_norm) or not os.path.isfile(file_path_norm):
        logger.error(f"文件无效: {file_path}")
        return False, f"无效文件路径: {file_path}"
    
    # 尝试获取文件权限
    if not enable_privilege(SE_RESTORE_NAME):
        return False, "SE_RESTORE_NAME特权未启用"
        
    # 初始化哈希对象
    hash_objs = {}
    for alg in algorithms:
        if alg == 'CRC32':
            hash_objs[alg] = 0
        elif alg == 'MD5':
            hash_objs[alg] = hashlib.md5()
        elif alg == 'SHA-256':
            hash_objs[alg] = hashlib.sha256()
        elif alg == 'SHA-512':
            hash_objs[alg] = hashlib.sha512()
    
    # 循环尝试读取文件并计算哈希
    for retry in range(MAX_RETRY_COUNT):
        try:
            # 使用Windows API打开文件以支持长路径和特殊权限
            handle = kernel32.CreateFileW(
                file_path_norm,
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None
            )
            
            if handle == ctypes.wintypes.HANDLE(-1).value:
                error_code = ctypes.GetLastError()
                if error_code == 5 and take_ownership(file_path_norm):
                    # 权限错误，尝试获取所有权后重试
                    if retry < MAX_RETRY_COUNT - 1:
                        logger.info(f"重试处理文件 {file_path}，尝试 {retry + 2}/{MAX_RETRY_COUNT}")
                        time.sleep(0.5)
                        continue
                    return False, "权限错误，已尝试获取所有权"
                return False, f"无法打开文件: {ctypes.FormatError(error_code)}"
            
            try:
                buffer = ctypes.create_string_buffer(BUFFER_SIZE)  # 使用更大的缓冲区提高效率
                bytes_read = ctypes.wintypes.DWORD(0)
                
                while kernel32.ReadFile(handle, buffer, ctypes.sizeof(buffer), byref(bytes_read), None) and bytes_read.value > 0:
                    data = buffer.raw[:bytes_read.value]
                    
                    # 更新各个哈希值
                    for alg in algorithms:
                        if alg == 'CRC32':
                            hash_objs[alg] = zlib.crc32(data, hash_objs[alg])
                        else:
                            hash_objs[alg].update(data)
            finally:
                kernel32.CloseHandle(handle)
            
            # 生成最终哈希值
            hashes = {}
            for alg in algorithms:
                if alg == 'CRC32':
                    hashes[alg] = hex(hash_objs[alg] & 0xFFFFFFFF)[2:].upper().zfill(8)
                else:
                    hashes[alg] = hash_objs[alg].hexdigest()
                    
            return True, hashes
            
        except PermissionError:
            if retry < MAX_RETRY_COUNT - 1:
                logger.info(f"重试处理文件 {file_path}，尝试 {retry + 2}/{MAX_RETRY_COUNT}")
                time.sleep(0.5)
                continue
            return False, f"权限错误: {file_path}"
        except Exception as e:
            if retry < MAX_RETRY_COUNT - 1:
                logger.info(f"重试处理文件 {file_path}，尝试 {retry + 2}/{MAX_RETRY_COUNT}")
                time.sleep(0.5)
                continue
            logger.error(f"读取文件时出错 {file_path}: {str(e)}")
            return False, f"读取文件错误: {str(e)}"
    
    return False, f"多次尝试失败: {file_path}"

def save_to_database(results, db_path, auto_parse=True):
    """批量保存结果到数据库，优化版"""
    if not results:
        return 0
    
    try:
        db_path_norm = normalize_path(db_path, auto_parse)
        
        # 确保数据库目录存在
        db_dir = os.path.dirname(db_path_norm)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            
        with sqlite3.connect(db_path_norm) as conn:
            cursor = conn.cursor()
            # 创建表时添加索引以提高查询效率
            cursor.execute('''CREATE TABLE IF NOT EXISTS hashes
                              (file_path TEXT PRIMARY KEY, write_time TEXT, 
                               MD5 TEXT, CRC32 TEXT, SHA_256 TEXT, SHA_512 TEXT)''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON hashes(file_path)')
            
            write_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.executemany('''INSERT OR REPLACE INTO hashes 
                                 (file_path, write_time, MD5, CRC32, SHA_256, SHA_512) 
                                 VALUES (?,?,?,?,?,?)''', 
                              [(p, write_time, m, c, s256, s512) for p, m, c, s256, s512 in results])
            conn.commit()
            return len(results)
    except Exception as e:
        logger.error(f"数据库保存失败: {e}")
        return 0

# 多线程文件处理
def process_files(file_paths, algorithms, db_path, progress_bar, auto_parse=True):
    """处理文件/目录，优化版"""
    try:
        # 路径处理
        normalized_paths = []
        for path in file_paths:
            try:
                if auto_parse:
                    normalized_path = normalize_path(os.path.abspath(os.path.expandvars(path)))
                else:
                    normalized_path = path
                
                if not os.path.exists(normalized_path):
                    return 0, 0, f"路径不存在: {path}"
                
                normalized_paths.append(normalized_path)
            except Exception as e:
                return 0, 0, f"路径处理失败: {str(e)}"
        
        # 处理数据库路径
        if auto_parse:
            db_path_norm = normalize_path(os.path.abspath(os.path.expandvars(db_path)))
        else:
            db_path_norm = db_path
        
        # 收集所有文件
        all_files = []
        for path in normalized_paths:
            if os.path.isfile(path):
                if path != db_path_norm:
                    all_files.append(path)
            else:  # 目录
                # 优化目录遍历，使用生成器方式减少内存占用
                for root, _, files in os.walk(path):
                    for f in files:
                        fp = os.path.join(root, f)
                        if fp != db_path_norm:
                            all_files.append(fp)
        
        total_files = len(all_files)
        if total_files == 0:
            return 0, 0, "未找到有效文件"

        # 处理文件
        success_count = 0
        fail_count = 0
        error_messages = []
        processed = AtomicCounter()

        def update_progress():
            p = processed.increment()
            if total_files > 0:
                wx.CallAfter(progress_bar.SetValue, min(int(p / total_files * 100), 100))

        # 动态优化线程池大小 - 根据文件数量和CPU核心数调整
        cpu_count = os.cpu_count() or 4
        # 对于少量文件，使用较少的线程；对于大量文件，使用更多线程
        max_workers = min(
            cpu_count * 2 if total_files < 100 else cpu_count * 4,  
            32,  # 最大线程数上限
            max(2, total_files // 10)  # 至少2个线程，且与文件数量成正比
        )
        
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="HashCalc") as executor:
            # 提交任务时避免创建临时列表，直接提交生成器
            futures = {executor.submit(process_file, fp, algorithms, auto_parse): fp for fp in all_files}
            batch = []
            
            for future in as_completed(futures):
                success, result = future.result()
                update_progress()
                
                if success:
                    batch.append((futures[future], result.get('MD5', ''), result.get('CRC32', ''), 
                                  result.get('SHA-256', ''), result.get('SHA-512', '')))
                    # 批量提交减少数据库操作
                    if len(batch) >= BATCH_SIZE:
                        success_count += save_to_database(batch, db_path_norm, False)
                        batch = []
                else:
                    fail_count += 1
                    error_messages.append(f"{futures[future]}: {result}")
            
            # 处理剩余的批
            if batch:
                success_count += save_to_database(batch, db_path_norm, False)

        # 限制错误消息数量
        error_summary = "\n".join(error_messages[:10])
        if len(error_messages) > 10:
            error_summary += f"\n... 还有 {len(error_messages) - 10} 个错误未显示"
            
        return success_count, fail_count, error_summary
    except Exception as e:
        logger.error(f"处理文件集合失败: {str(e)}")
        return 0, 0, f"处理文件集合失败: {str(e)}"

# GUI界面
class HashCalculatorGUI(wx.Frame):
    def __init__(self, parent, title):
        super().__init__(parent, title=title, size=(600, 400))
        self.Bind(wx.EVT_ACTIVATE, self.on_activate)
        self.auto_parse_path = True
        self.start_btn = None
        self.panel = wx.Panel(self)
        self.panel.SetBackgroundColour(wx.SystemSettings.GetColour(wx.SYS_COLOUR_WINDOW))
        self.init_ui()
        self.Centre()
        self.Show()

    def on_activate(self, event):
        self.panel.SetBackgroundColour(wx.Colour(236,246,249) if event.GetActive() else wx.Colour(243,243,243))
        event.Skip()
        self.Refresh()

    def init_ui(self):
        # 哈希算法选择
        alg_box = wx.BoxSizer(wx.HORIZONTAL)
        self.md5 = wx.CheckBox(self.panel, label="MD5")
        self.crc32 = wx.CheckBox(self.panel, label="CRC32")
        self.sha256 = wx.CheckBox(self.panel, label="SHA-256")
        self.sha512 = wx.CheckBox(self.panel, label="SHA-512")
        self.auto_parse_checkbox = wx.CheckBox(self.panel, label="解析环境变量")
        self.auto_parse_checkbox.SetValue(self.auto_parse_path)
        self.auto_parse_checkbox.Bind(wx.EVT_CHECKBOX, self.on_auto_parse_toggle)
        
        alg_box.AddMany([(self.md5, 0, wx.LEFT, 20), (self.crc32, 0, wx.LEFT, 20),
                        (self.sha256, 0, wx.LEFT, 20), (self.sha512, 0, wx.LEFT, 20),
                        (self.auto_parse_checkbox, 0, wx.LEFT, 20)])

        # 路径选择
        path_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.b1 = wx.Button(self.panel, label="浏览", id=1)
        path_sizer.Add(self.b1, 0, wx.LEFT | wx.TOP, 20)
        self.path_text = wx.TextCtrl(self.panel)
        self.path_text.SetHint("请在此输入文件或文件夹路径")
        path_sizer.Add(self.path_text, 1, wx.LEFT | wx.TOP | wx.RIGHT, 20)

        # 数据库路径
        db_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.b2 = wx.Button(self.panel, label="浏览", id=2)
        db_sizer.Add(self.b2, 0, wx.LEFT | wx.TOP, 20)
        self.db_text = wx.TextCtrl(self.panel)
        self.db_text.SetHint("请在此输入数据库生成路径")
        db_sizer.Add(self.db_text, 1, wx.LEFT | wx.TOP | wx.RIGHT, 20)

        # 自动线程数提示
        cpu_count = os.cpu_count() or 4
        thread_count = min(cpu_count * 2, 32)
        thread_hint = wx.StaticText(self.panel, label=f"自动优化已开启 当前{thread_count}线程")

        self.progress = wx.Gauge(self.panel, range=100)
        self.status = wx.StaticText(self.panel, label="就绪")

        # 布局
        main_sizer = wx.BoxSizer(wx.VERTICAL)
        main_sizer.Add(alg_box, 0, wx.TOP, 20)
        main_sizer.Add(path_sizer, 0, wx.EXPAND)
        main_sizer.Add(db_sizer, 0, wx.EXPAND)
        main_sizer.Add(thread_hint, 0, wx.LEFT | wx.TOP, 20)
        main_sizer.Add(self.progress, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.TOP, 20)
        main_sizer.Add(self.status, 0, wx.LEFT | wx.TOP, 20)
        
        # 开始按钮
        self.start_btn = wx.Button(self.panel, label="开始计算", id=3)
        main_sizer.Add(self.start_btn, 0, wx.LEFT | wx.TOP | wx.BOTTOM, 20)
        
        self.panel.SetSizer(main_sizer)
        
        # 绑定事件
        self.Bind(wx.EVT_BUTTON, self.on_select_path, id=1)
        self.Bind(wx.EVT_BUTTON, self.on_select_db_path, id=2)
        self.Bind(wx.EVT_BUTTON, self.on_start, id=3)
        
        # 算法选择事件
        for cb in [self.md5, self.crc32, self.sha256, self.sha512]:
            cb.Bind(wx.EVT_CHECKBOX, self.on_algorithm_change)
            
        # 文本框事件
        for txt in [self.path_text, self.db_text]:
            txt.Bind(wx.EVT_KILL_FOCUS, self.on_text_blur)
            txt.Bind(wx.EVT_TEXT, self.on_text_change)
            txt.Bind(wx.EVT_SET_FOCUS, self.on_text_focus)

        self.update_start_button_state()

    def on_text_focus(self, event):
        event.Skip()
        self.Refresh()

    def on_auto_parse_toggle(self, event):
        self.auto_parse_path = self.auto_parse_checkbox.GetValue()
        for txt in [self.path_text, self.db_text]:
            if txt.GetValue():
                self.on_text_blur(None)

    def expand_environment_variables(self, text):
        if not text or not self.auto_parse_path:
            return text
        try:
            return os.path.expandvars(text)
        except Exception as e:
            logger.error(f"环境变量解析错误: {e}")
            return text

    def on_text_blur(self, event):
        if event: 
            event.Skip()
            txt = event.GetEventObject()
        else:
            # 如果没有事件对象，获取当前活动控件
            txt = wx.Window.FindFocus()
            if not isinstance(txt, wx.TextCtrl):
                return
        
        txt.SetSelection(0, 0)
        text = txt.GetValue()
        if text:
            expanded = self.expand_environment_variables(text)
            if expanded != text:
                txt.SetValue(expanded)
        self.update_start_button_state()

    def on_text_change(self, event):
        self.update_start_button_state()

    def on_algorithm_change(self, event):
        self.update_start_button_state()

    def update_start_button_state(self):
        if not self.start_btn: 
            return
        
        has_algorithm = self.md5.GetValue() or self.crc32.GetValue() or self.sha256.GetValue() or self.sha512.GetValue()
        has_path = bool(self.path_text.GetValue().strip())
        has_db_path = bool(self.db_text.GetValue().strip())
        
        self.start_btn.Enable(has_algorithm and has_path and has_db_path)

    def on_select_path(self, event):
        # 使用wx.SingleChoiceDialog实现单选效果
        choices = ["文件", "文件夹"]
        dlg = wx.SingleChoiceDialog(
            self, 
            "请选择要添加的类型", 
            "选择类型", 
            choices
        )
        
        try:
            if dlg.ShowModal() == wx.ID_OK:
                selection = dlg.GetStringSelection()
                if selection == "文件":
                    # 文件选择对话框
                    file_dialog = wx.FileDialog(self, "选择文件", wildcard="所有文件 (*.*)|*.*",
                                              style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST | wx.FD_MULTIPLE)
                    try:
                        if file_dialog.ShowModal() == wx.ID_OK:
                            self.path_text.SetValue(';'.join(file_dialog.GetPaths()))
                    finally:
                        file_dialog.Destroy()
                elif selection == "文件夹":
                    # 文件夹选择对话框
                    folder_dialog = wx.DirDialog(self, "选择文件夹", style=wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST)
                    try:
                        if folder_dialog.ShowModal() == wx.ID_OK:
                            self.path_text.SetValue(folder_dialog.GetPath())
                    finally:
                        folder_dialog.Destroy()
        finally:
            dlg.Destroy()
        
        self.update_start_button_state()

    def on_select_db_path(self, event):
        dialog = wx.FileDialog(self, "保存数据库文件", wildcard="SQLite数据库 (*.db)|*.db",
                              style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        try:
            if dialog.ShowModal() == wx.ID_OK:
                path = dialog.GetPath()
                self.db_text.SetValue(path if path.endswith('.db') else f"{path}.db")
        finally:
            dialog.Destroy()
        
        self.update_start_button_state()

    def on_start(self, event):
        # 获取选中的算法
        algorithms = self.get_selected_algorithms()
        path_text = self.path_text.GetValue().strip()
        db_path = self.db_text.GetValue().strip()
        
        if not algorithms or not path_text or not db_path:
            wx.MessageBox("请选择至少一种算法并填写完整路径", "错误", wx.OK | wx.ICON_ERROR)
            return
            
        file_paths = [p.strip() for p in path_text.split(';') if p.strip()]
        
        # 禁用控件
        self.disable_controls()
        self.status.SetLabel("正在计算...")
        self.progress.SetValue(0)
        
        # 后台任务
        def background_task():
            success, fail, errors = process_files(
                file_paths, algorithms, db_path, self.progress, self.auto_parse_path
            )
            wx.CallAfter(self.on_task_complete, success, fail, errors)
            
        threading.Thread(target=background_task, daemon=True).start()
        
    def get_selected_algorithms(self):
        """获取用户选择的哈希算法"""
        algorithms = []
        for alg, cb in [("MD5", self.md5), ("CRC32", self.crc32), 
                       ("SHA-256", self.sha256), ("SHA-512", self.sha512)]:
            if cb.GetValue():
                algorithms.append(alg)
        return algorithms
        
    def disable_controls(self):
        """禁用所有输入控件"""
        for ctrl in [self.start_btn, self.b1, self.b2, self.md5, self.crc32, 
                    self.sha256, self.sha512, self.path_text, self.db_text, 
                    self.auto_parse_checkbox]:
            ctrl.Disable()
        
    def enable_controls(self):
        """启用所有输入控件"""
        for ctrl in [self.start_btn, self.b1, self.b2, self.md5, self.crc32, 
                    self.sha256, self.sha512, self.path_text, self.db_text, 
                    self.auto_parse_checkbox]:
            ctrl.Enable()

    def on_task_complete(self, success, fail, errors):
        # 启用控件
        self.enable_controls()
        
        # 更新状态
        self.progress.SetValue(100)
        self.update_status_and_show_message(success, fail, errors)
        
    def update_status_and_show_message(self, success, fail, errors):
        """根据处理结果更新状态并显示消息"""
        if fail == 0 and success > 0:
            self.status.SetLabel(f"完成: 成功 {success} 个，失败 {fail} 个")
            wx.MessageBox(f"计算完成！成功处理 {success} 个文件", "完成", wx.OK | wx.ICON_INFORMATION)
        elif success == 0 and fail > 0:
            self.status.SetLabel(f"全部失败: 共 {fail} 个")
            wx.MessageBox(f"所有文件处理失败！\n{errors}", "错误", wx.OK | wx.ICON_ERROR)
        else:
            self.status.SetLabel(f"部分完成: 成功 {success} 个，失败 {fail} 个")
            wx.MessageBox(f"部分文件处理失败！\n{errors}", "警告", wx.OK | wx.ICON_WARNING)


def main():
    # 启动时自动检查并获取管理员权限
    if not is_admin():
        # 尝试启动管理员进程
        if run_as_admin():
            # 启动成功后，原进程立即退出
            sys.exit(0)
        else:
            # 启动失败，显示错误后退出
            app = wx.App(False)
            wx.MessageBox("该程序正常运行需要管理员权限启动", "权限错误", wx.OK | wx.ICON_ERROR)
            return
    
    # 只有管理员进程会执行到这里，显示主窗口
    app = wx.App(False)
    HashCalculatorGUI(None, "文件哈希计算器")
    app.MainLoop()

if __name__ == "__main__":
    main()
