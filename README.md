# IoT-Home-Guard

IoT-Home-Guard is a project to help people discover malware in home smart devices. It contains a software tool and a hardware tool.

If you find that your smart device in your home has strange behavior, or if you only suspect that a device has been implanted with a Trojan, you can use these tools to confirm.

In July 2018 I had completed the first version of the software and hardware. I will complete the second version by October 2018, when the user experience and the number of identifiable devices will be greatly improved.

## Proof of principle

Our approach is based on the detection of malicious network traffic. A device implanted malwares will communicate with remote server, trigger a remote shell or send audios/videos to server.

The chart below shows the network traffic of a device implanted malwares.
Red line : traffic between devices and a remote server.
Green line : normal traffic of devices.
Black line : Sum of TCP traffic.

	![mi-listen&wakeup][./mi-listen&wakeup.png]


## Supported Devices

Device Name | Product Version |
:---------: | :---------:|
Xiaomi MINI smart speaker | LX01 |
Amazon Echo v1 smart speaker | v1 |
Amazon Echo v2 smart speaker | v2 |
Xiaofang ip camera | iSC5 |
Baidu WiFi Translator | TUGE830 |
Xiaomi Mijia driving recorder | ZNHSJ01BY |
Netease Youdao smart translator | GTA07 |

## Modules of IoT-Home-Guard

1. AP module and Data flow catcher: Catch network traffic.
2. Traffic analying engine: Extract characteristics from network traffic and compare them with device fingerprint database.
3. Device fingerprint database: Normal network behaviors of each devices, based on whitelist. Call APIs of 360 threat intelligence database ([https://ti.360.net/](https://ti.360.net/)).
4. Web server: There may be a web server in the second generation. 

## Procedure of IoT-Home-Guard

                                               ___________________       ___________________
                                              |                   |     |                   |
                                              | data_flow_catcher |<----| devices connected |
                                              |___________________|     |___________________|
                                                   ¦
                                                   ¦
     ____________________________              ____↓________________  
    |                            |            |                     |
    | device_fingerprint_databse |<---------> | flow_analyze_engine |
    |____________________________|       ¦    |_____________________|
                                         ¦         ↑
                                         ¦         ¦
     __________________________________  ¦     ____↓_______              _________________
    |                                  | ¦    |            |            |                 |
    | 360 threat intelligence database |<-    | web_server |<-----------| user interfaces |
    |__________________________________|      |____________|            |_________________|

## Tutorials of IoT-Home-Guard

For a hardware tool, see IoT-Home-Guard/Hardware_tool/README.md
For a software tool, see IoT-Home-Guard/Software_tool/README.md
