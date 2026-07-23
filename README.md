===========================================================================
# 产品介绍

#外观尺寸：

#外壳材质：

#电池容量：

#屏幕尺寸&分辨率：

#flash容量：

#温度范围：

#MCU1，MCU2介绍：

#硬件版本：

#软件版本：

#功能介绍：

===========================================================================
# 开机画面
#用户可以自定义

#点击弹出 PIN码 密码输入，Machine-PIN码可以设置

#输入错误PIN码 进入B系统内无数据

#连续5次输入错误PIN码锁定1min


===========================================================================
# 顶部状态栏
#时间

#电池电量

#NFC状态

#工作模式[U盘模式、ESP32模式、chameleon模式]

============================================================================
# USB选择
#USB msc U盘模式 上电默认不初始化出来-通过按钮切换选择是否虚拟出U盘模式。

#USB 上电默认是 接esp32-p4 虚拟出 hid，fido，smartcard

#USB nrf 模式可以通过 按钮选择切换

============================================================================ 
# 功能

#支持 keepass  KDBX4.1 数据库解析。

#支持 10 FIDO2。

#支持 5solt  OpenPGP。

#支持 5solt  PIV。

#支持 chameleon 卡片8张。

#JADE 硬件钱包支持

#Miixkey3的脚本是一个USB HID 注入工具，支持执行类似 USB Rubber Ducky 的脚本语言

=============================================================================
# 系统设置

#支持时间，温度，电量检测

#支持 OTA 软件持续升级

#支持硬件算法加密

#支持自定义桌面

#支持多语言切换（中/英）

============================================================================== 
# 关于
开源声明：chameleon、canokey-core、LVGL、Rubber Ducky 、JADE、freeRTOS、

============================================================================== 

# 测试工具

#keepass

#fido2

#piv

#OpenPGP

#Rubber Ducky

#JADE

#Chameleon


============================================================================== 



## Troubleshooting

* Program upload failure

    * Hardware connection is not correct: run `idf.py -p PORT monitor`, and reboot your board to see if there are any output logs.
    * The baud rate for downloading is too high: lower your baud rate in the `menuconfig` menu, and try again.

## Technical support and feedback

Please use the following feedback channels:

* For technical queries, go to the [esp32.com](https://esp32.com/) forum
* For a feature request or bug report, create a [GitHub issue](https://github.com/espressif/esp-idf/issues)

We will get back to you as soon as possible.
