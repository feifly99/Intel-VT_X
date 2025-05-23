# Intel-VT_X

    成功实现全核心虚拟化，一个驱动虚拟12个核心！
    但是卸载逻辑还没有写！
    删除了单独虚拟化的文件，用不上了
    明天记录一下出现的错误和才过的坑！


    新加的两个纯单核的文件
    只要需要修改Purely_entry.c的currentVMCSCpuIndex就可以
    对指定核心虚拟化
    
    已经成功实现基本VT框架，支持对CPUID/RDMSR/WRMSR指令的拦截
    增加了vmxoff逻辑，补充了驱动卸载并释放了相关内存
    无内存泄漏，可以多次启动或卸载
    可平稳运行在如下物理真实硬件环境
    INTEL® Core™ i7 - 9750H  Coffee Lake架构CPU
    Windows 10 x64 - 22H2
    无异常表现
    就酱~
    
    对于Unconditionally的某些指令并没有处理
    遇到非CPUID/RDMSR/WRMSR指令会自动int 3断下或者主动蓝屏
    但因为似乎我的Cpu和Os不会主动执行那些指令
    所以即使是int 3或者bugCheck也不会触发
    
    第三作用域不用设置，我的CPU没有对应的第三控制域MSR！
    中嘞！

    第二作用域和第三作用域都得设置，不同于周壑老师的32位单核单线程环境
    因此主作用域的bit 17和bit 31都得置1来支持二三作用域（第三作用域不用设置了，没有对应的MSR-_-）
    因为不设置相应位，执行到在二三控制域的指令（比如RDTSCP）会导致#UD
    并且不会被HOST接管直接蓝屏，代码：SYSTEM_THREAD_EXCEPTION_NOT_HANDLED
    原因：0xC000001D -> 处理器不支持的指令

    现在能进入HOST_ENTRY了！HOST_ENTRY必须用汇编写，不能用C写
    因为VS2022 x64模式不允许声明naked裸函数

    硬件架构 
    INTEL® Core™ i7 - 9750H  Coffee Lake架构CPU
    Windows 10 x64 - 22H2
    
  VT练习
