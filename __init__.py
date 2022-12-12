from binaryninja import BinaryView, DisassemblyTextLine, log_info
from binaryninja.enums import (
    BranchType,
    HighlightStandardColor,
    InstructionTextTokenType,
)
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.function import InstructionTextToken
from binaryninja.plugin import PluginCommand
from binaryninjaui import (
    ClickableIcon,
    ContextMenuManager,
    FlowGraphWidget,
    Menu,
    StatusBarWidget,
    UIAction,
    UIActionHandler,
    UIContext,
    ViewType,
)
from PySide6.QtCore import QSize
from PySide6.QtGui import QImage, QPalette
from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget


class CallGraph(FlowGraph):
    def __init__(self, func):
        super(CallGraph, self).__init__()
        self.function = func
        self.bv = func and func.view
        self.func_dict = {}

        # # Support user annotations for this graph
        self.uses_block_highlights = True
        self.uses_instruction_highlights = True
        self.includes_user_comments = True
        self.shows_secondary_reg_highlighting = True

    def get_unique_calls(self, func):
        unique_calls = {}
        callers = func.callers
        for caller in callers:
            if caller.name not in unique_calls.keys():
                unique_calls[caller.start] = caller
        return unique_calls

    def find_node(self, addr):
        if addr in self.func_dict.keys():
            return self.func_dict[addr]
        return None

    def populate_nodes(self):
        if self.function:
            self.create_nodes(self.function)

    def create_nodes(self, func):
        func_node = FlowGraphNode(self)
        if func.get_instr_highlight(func.start).color == 2:
            func_node.highlight = HighlightStandardColor.GreenHighlightColor
        else:
            func_node.highlight = HighlightStandardColor.NoHighlightColor
        line = []
        if self.bv.session_data['show_address'] == True:
            line.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, hex(func.start)[2:], func.start))
            line.append(InstructionTextToken(InstructionTextTokenType.TextToken, ": "))
        if self.bv.session_data['show_sigs'] == True:
            line.extend(func.function_type.get_tokens_before_name())
            line.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
        line.append(InstructionTextToken(InstructionTextTokenType.CodeSymbolToken, func.name, func.start))
        if self.bv.session_data['show_sigs'] == True:
            line.extend(func.function_type.get_tokens_after_name())
        func_node.lines = [DisassemblyTextLine(line)]
        self.func_dict[func.start] = func_node
        self.append(func_node)
        for caller_addr, caller in self.get_unique_calls(func).items():
            old_node = self.find_node(caller_addr)
            if old_node != None:
                func_node.add_outgoing_edge(BranchType.UnconditionalBranch, old_node)
            else:
                call_node = self.create_nodes(caller)
                func_node.add_outgoing_edge(BranchType.UnconditionalBranch, call_node)
        return func_node

    def update(self):
        return CallGraph(self.function)


class CallGraphView(FlowGraphWidget):
    def __init__(self, parent, data: BinaryView, addr=None):
        self.data: BinaryView = data
        self.vf = parent

        # TODO: persist these somewhere (Settings or something)
        self.data.session_data['show_address'] = False
        self.data.session_data['show_sigs'] = False

        self.function = None
        graph = None
        if addr and self.data.is_valid_offset(addr):
            self.function = (functions := data.get_functions_containing(addr)) and functions[0]
            graph = CallGraph(self.function)
        # print("f", self.function)

        super().__init__(parent, self.data, graph)

    # Note: Need this for CallGraphOptions
    @property
    def call_graph_view(self):
        return self

    def getCurrentOffset(self):
        addr = super().getCurrentOffset()
        if not addr:
            func = self.getCurrentFunction()
            if func:
                addr = func.start
        return addr

    def getHeaderOptionsWidget(self):
        options = OptionsIconWidget(self, CallGraphOptions(self))
        return options

    def navigate(self, addr):
        print("wut", hex(addr))
        self.data = self.getData()
        block = self.data.get_recent_basic_block_at(addr)
        if block is None:
            func = self.data.get_recent_function_at(addr)
        else:
            func = block.function
        print("funcy", func)
        if func is None:
            return False

        return self.navigateToFunction(func, addr)

    def navigateToFunction(self, func, addr):
        self.function = self.getCurrentFunction()
        if func == self.function:
            self.showAddress(addr, True)
            # return True

        self.function = func
        self.graph = CallGraph(func)
        print("now here", hex(addr))
        self.setGraph(self.graph, addr)
        return True

    def navigateToViewLocation(self, vl, center=False):
        func = vl.getFunction()
        addr = vl.getOffset()
        return self.navigateToFunction(func, addr)

    def getStatusBarWidget(self):
        return CallGraphMenu(self)


class CallGraphViewType(ViewType):
    def __init__(self):
        super(CallGraphViewType, self).__init__("Call", "Call Graph View")

    def getPriority(self, data, filename):
        if data.executable:
            return 1
        return 0

    def create(self, data, view_frame, address=None):
        return CallGraphView(view_frame, data, address)


# Note: this is no longer a widget, but a container for the options menu so it can be used
# from both the status bar menu and the hamburger menu
class CallGraphOptions:
    def __init__(self, call_graph_view_container):   
        self.call_graph_view_container = call_graph_view_container
        self.menu = Menu()
        self.actionHandler = UIActionHandler()
        self.registerActions()
        self.addActions()
        self.bindActions()

    @property
    def call_graph_view(self):
        return self.call_graph_view_container.call_graph_view

    def registerActions(self):
        UIAction.registerAction("Show Function Signatures")
        UIAction.registerAction("Show Addresses")
        UIAction.registerAction("Highlight Functions")

    def addActions(self):
        self.menu.addAction("Show Function Signatures", "Options")
        self.menu.addAction("Show Addresses", "Options")
        self.menu.addAction("Highlight Functions", "Options")

    def bindActions(self):
        self.actionHandler.bindAction("Show Function Signatures", UIAction(self.on_show_func_sigs))
        self.actionHandler.setChecked("Show Function Signatures", lambda _: self.show_func_sigs)
        self.actionHandler.bindAction("Show Addresses", UIAction(self.on_show_addresses))
        self.actionHandler.setChecked("Show Addresses", lambda _: self.show_addresses)
        self.actionHandler.bindAction("Highlight Functions", UIAction(self.on_highlight))
        # TODO: uncomment if this property exists (see comment on on_highlight)
        # self.actionHandler.setChecked("Highlight Functions", lambda _: self.highlight_functions)

    @property
    def show_func_sigs(self) -> bool:
        if 'show_sigs' in self.call_graph_view.data.session_data:
            return self.call_graph_view.data.session_data['show_sigs']
        return False

    @show_func_sigs.setter
    def show_func_sigs(self, flag: bool) -> None:
        self.call_graph_view.data.session_data['show_sigs'] = flag

    @property
    def show_addresses(self) -> bool:
        if 'show_address' in self.call_graph_view.data.session_data:
            return self.call_graph_view.data.session_data['show_address']
        return False

    @show_addresses.setter
    def show_addresses(self, flag: bool) -> None:
        self.call_graph_view.data.session_data['show_address'] = flag

    # DONE: do check mark later
    # DONE: need to make update
    def on_show_func_sigs(self, uiActionContext):
        self.show_func_sigs = not self.show_func_sigs
        func = self.call_graph_view.function.start
        self.call_graph_view.navigate(func)

    def on_show_addresses(self, uiActionContext):
        self.show_addresses = not self.show_addresses
        func = self.call_graph_view.function.start
        self.call_graph_view.navigate(func)

    # TODO: this probably needs a checkbox too, but I'm not sure what the toggle logic really should be
    def on_highlight(self, uiActionContext):
        addr = list(self.call_graph_view.graph.func_dict.keys())[0]
        func = self.call_graph_view.data.get_functions_containing(addr)[0]
        if func.get_instr_highlight(func.start).color == 0:
            for addr in self.call_graph_view.graph.func_dict.keys():
                func = self.call_graph_view.data.get_functions_containing(addr)[0]
                for a in range(func.address_ranges[0].start, func.address_ranges[0].end):
                    func.set_user_instr_highlight(a, HighlightStandardColor.GreenHighlightColor)
        else:
            for addr in self.call_graph_view.graph.func_dict.keys():
                func = self.call_graph_view.data.get_functions_containing(addr)[0]
                for a in range(func.address_ranges[0].start, func.address_ranges[0].end):
                    func.set_user_instr_highlight(a, HighlightStandardColor.NoHighlightColor)

        func = self.call_graph_view.function.start
        self.call_graph_view.navigate(func)


class CallGraphMenu(StatusBarWidget):
    def __init__(self, parent):
        StatusBarWidget.__init__(self, parent)

        self.call_graph_view = parent
        self.contextMenuManager = ContextMenuManager(self)

        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.options = CallGraphOptions(parent)
        self.menu_label = QLabel(self)
        self.menu_label.setText("Options ▾ ")

        self.layout.addWidget(self.menu_label)

    def mousePressEvent(self, event):
        print("gang")
        self.contextMenuManager.show(self.options.menu, self.options.actionHandler)

    #  ~~IDK Y not working~~ is working now
    def enterEvent(self, event):
        self.menu_label.setAutoFillBackground(True)
        self.menu_label.setForegroundRole(QPalette.HighlightedText)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.menu_label.setAutoFillBackground(False)
        self.menu_label.setForegroundRole(QPalette.WindowText)
        super().leaveEvent(event)


class OptionsIconWidget(QWidget):
    def __init__(self, parent, options):
        super().__init__(parent)
        self.options = options
        self.contextMenuManager = ContextMenuManager(self)
        self.menu = None

        icon = ClickableIcon(QImage(":/icons/images/menu.png"), QSize(16, 16))
        icon.clicked.connect(self.showMenu)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(icon)
        self.setLayout(layout)

    def showMenu(self):
        if self.options and self.options.menu:
            self.contextMenuManager.show(self.options.menu, self.options.actionHandler)

    def setOptions(self, options):
        self.options = options


def view_call_graph(bv, addr_or_function):
    if hasattr(addr_or_function, 'start'):
        addr = addr_or_function.start
    elif type(addr_or_function) is int:
        addr = addr_or_function
    else:
        raise ValueError("parameter must be a function or an address")
    view_type = bv.view.split(':')[1]
    log_info(f'view_call_graph({addr_or_function=!r}): {addr:#x} {view_type=}')
    bv.navigate("Call:" + view_type, addr)


ViewType.registerViewType(CallGraphViewType())
PluginCommand.register_for_function("View in Call Graph", "View Call Graph", view_call_graph)
PluginCommand.register_for_address("View in Call Graph", "View Call Graph", view_call_graph)