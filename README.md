# Intel-VT_X

    Minimal: 仅支持最基础，最简单的VT-x环境，没有任何拓展，是最最简单的入门文件夹；
    EPT：    在VT-x的基础上，增加了EPT特性，并测试了对NtOpenProcess的EPT劫持；
    Extension：结合Intel® VT 和 EPT/ MTF特性的，没有用户层交互的，调试器功能demo集合；
    UserKrnlInteraction： 结合结合Intel® VT 和 EPT/ MTF特性的，配备用户层交互的，调试器功能集成版，支持动态拓展和数据结构管理，稍加改动就可以直接真正实用的版本。

    以上四个文件夹，Minimal和EPT已经开发完毕，不会再次更改；Extension和UserKrnlInteraction都正在处于开发状态。作者QQ: 1906106581.

    为什么我要写这个项目？
    当前可公开获取的 VT-x 学习资源要么是四五年前的过时代码，只支持 32 位单核系统；要么就是企业级虚拟化平台，代码庞杂复杂，难以直接学习。
    而不公开的VT资料就要花钱去买，而且很贵！
    本项目旨在填补这一空白，完全基于 Intel SDM 自主从零实现，目标是构建一个“能在现代多核硬件上运行、足够干净、容易学习的真实VMM”。
    如果你也在苦苦寻找一个能跑得起来、能看得懂、能调得动的虚拟化项目，希望本仓库能给你一点帮助。

    VT-X Minimal中，作了如下更新：
    1.手动保存恢复x87FPU/AVX/SSE状态；
    2.在VT卸载后，修复GDT/IDT的Limit段限制(0x57ui16 & 0xFFFui16)；
    3.删除了旧的vt.asm和vt_plus.asm，换成了全新的vt.asm；
    4.在vmxoff前，对每个处理器执行了vmclear.

    另外，VT的HOST_ENTRY中尽量不要手动管理CRX & DRX寄存器：
    1.CR3.mov to CR3会导致缓存不一致；
    2.CR4.mov to CR4的某些位需要用INVVPID去刷新。
    3.就算保存了，最后还是通过GUEST的区域由硬件CPU恢复。
    通过VMWRITE写入的CR3和直接mov to CR3机制不同，前者不会导致缓存不一致！

    Minimal和EPT文件夹下新增了两个vt_plus.asm，是之前vt.asm的简化整合版！
    之前的vt.asm中，所有的逻辑都在__vsm__hostEntry中，十分臃肿难读
    新加入的plus版本在原来的基础上做了大幅度的重构和逻辑删减，保持逻辑功能正常的情况下简化文件尺寸
    plus版本已经在物理机上通过测试，具体测试如下：
        1.EPT对NtOpenProcess的EPT HOOK正常工作；
        2.在开启上述HOOK的同时，能正常游玩一把COD5僵尸模式；
        3.游戏结束后，待机半小时，正常运行；
        4.在3结束后，对驱动进行5次反复启动和停止，正常运行；
        5.没有任何内存泄漏。
    但是尚未删除vt.asm，主要是考虑到vt.asm是最后一个可以完整正确还原运行逻辑的副本
    出现意外情况可以用最原来的vt.asm进行版本回滚。

    Extension文件夹内是结合了全部VT+EPT的综合实践，目前准备自建调试体系，刚刚起步。
    
    Intel® EPT已经能够在物理机内正常HOOK NtOpenProcess，已经毕业！！
    原因是在于配备物理页面的缓存属性时全部设置为#WB是不对的
    如何解决？看Intel开发人员手册Vol. 3. Chapter. 13的MTRR内存类型范围寄存器！
    把敏感物理内存页面的缓存属性用MSR读取！否则蓝屏报WHEA_UNCORRECTABLE_ERROR！！
    缓存属性设置正确后，Intel® VT+EPT能够正常运行了！

    在EPT文件夹内是配备Intel® EPT扩展页表技术的虚拟化实例，没内存泄露！
    在示例驱动中，对NtOpenProcess物理页面进行读写分离实现无痕拦截.
    基于此可以做相当多的事情！
    虚拟机可以正常运行，并正常实现基于读写分离的无痕拦截.
    但物理机还不能运行，蓝屏报WHEA_UNCORRECTABLE_ERROR.
    仍需要解决办法，准备使用双物理机Windbg调试.

    注意Intel® EPT扩展页表技术中对页面HOOK时
    一定不能对HOOK的页面进行读写执行全部覆盖！
    假页面和真页面的任何一个都不能全部满足读写执行三个权限.
    否则CPU的高速缓存不会进行刷新，只根据最近一次全部满足读写执行的页面进行寻址！
    必须把读写和执行分离开刻意触发EPT-Violation来强行刷新CPU对关键物理页面的高速缓存！

    成功实现了卸载逻辑，现在支持物理机器上反复安装卸载！
    没有任何内存泄漏！！！
    重构了getSegementRegisterAttributes()函数，更加简洁！
    
    成功实现全部核心虚拟化，一个驱动虚拟12个核心！
    但是卸载逻辑还没有写！
    删除了单独虚拟化的文件，用不上了.
    明天记录一下出现的错误和才过的坑！

    新加的两个纯单核的文件
    只要需要修改Purely_entry.c的currentVMCSCpuIndex就可以
    对指定核心虚拟化
    
    已经成功实现单核心VT框架，支持对CPUID/RDMSR/WRMSR指令的拦截
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
