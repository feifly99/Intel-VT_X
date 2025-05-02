# Intel-VT_X

    第二作用域和第三作用域都得设置，不同于周壑老师的环境
    因此主作用域的bit 17和bit 31都得置1来支持二三作用域
    因为不设置相应位，执行到在二三控制域的指令（比如RDTSCP）会导致#UD
    并且不会被HOST接管直接蓝屏，代码：SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
    原因：0xC000001D -> 处理器不支持的指令

    已经实现了最小的虚拟化环境
    驱动能正常加载、卸载和删除
    能拦截CPUID，尽管什么也没做
    还有RDMSR和WRMSR需要拦截

    现在能进入HOST_ENTRY了！HOST_ENTRY必须用汇编写，不能用C写
    因为VS2022 x64模式不允许声明naked裸函数

    硬件架构 
    INTEL® Core i7 - 9750H  Coffee Lake架构CPU
    Windows 10 x64 - 22H2
    
  VT练习
