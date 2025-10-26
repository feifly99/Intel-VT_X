.code

transPidAndIoRegion PROC
	mov eax, 0BCCCF000h
	cpuid
	ret
transPidAndIoRegion ENDP

addAddressToMonitor PROC
	mov eax, 0CCCCE000h
	cpuid
	ret
addAddressToMonitor ENDP

removeAddressFromMonitor PROC
	mov eax, 0ECCCD000h
	cpuid
	ret
removeAddressFromMonitor ENDP

startMonitoring PROC
	mov eax, 0AAAAAAAAh
	cpuid
	ret
startMonitoring ENDP

stopMonitoring PROC
	mov eax, 0BBBBBBBBh
	cpuid
	ret
stopMonitoring ENDP

END
