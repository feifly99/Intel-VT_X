# Intel-VT_X

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
