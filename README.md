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
开源声明：chameleon、canokey-core、LVGL、Rubber Ducky 、JADE

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





| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C6 | ESP32-C61 | ESP32-H2 | ESP32-P4 | ESP32-S2 | ESP32-S3 | Linux |
| ----------------- | ----- | -------- | -------- | -------- | -------- | --------- | -------- | -------- | -------- | -------- | ----- |

# Hello World Example

Starts a FreeRTOS task to print "Hello World".

(See the README.md file in the upper level 'examples' directory for more information about examples.)

## How to use example

Follow detailed instructions provided specifically for this example.

Select the instructions depending on Espressif chip installed on your development board:

- [ESP32 Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/stable/get-started/index.html)
- [ESP32-S2 Getting Started Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s2/get-started/index.html)


## Example folder contents

The project **hello_world** contains one source file in C language [hello_world_main.c](main/hello_world_main.c). The file is located in folder [main](main).

ESP-IDF projects are built using CMake. The project build configuration is contained in `CMakeLists.txt` files that provide set of directives and instructions describing the project's source files and targets (executable, library, or both).

Below is short explanation of remaining files in the project folder.

```
├── CMakeLists.txt
├── pytest_hello_world.py      Python script used for automated testing
├── main
│   ├── CMakeLists.txt
│   └── hello_world_main.c
└── README.md                  This is the file you are currently reading
```

For more information on structure and contents of ESP-IDF projects, please refer to Section [Build System](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html) of the ESP-IDF Programming Guide.

## Troubleshooting

* Program upload failure

    * Hardware connection is not correct: run `idf.py -p PORT monitor`, and reboot your board to see if there are any output logs.
    * The baud rate for downloading is too high: lower your baud rate in the `menuconfig` menu, and try again.

## Technical support and feedback

Please use the following feedback channels:

* For technical queries, go to the [esp32.com](https://esp32.com/) forum
* For a feature request or bug report, create a [GitHub issue](https://github.com/espressif/esp-idf/issues)

We will get back to you as soon as possible.
