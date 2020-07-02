---
title: Xposed留档
tags:
  - android
  - xposed
  - hook
date: 2019-04-07 16:10:58
---

# 简介
Xposed是Android常用的java层的hook框架。可以方便的对目标代码进行修改和监控
# 准备
- 已经root的android（如果使用VirtualXposed可以不root）
- 推荐使用[VirtualXposed](https://github.com/android-hacker/VirtualXposed "VirtualXposed Github")
- 当然还有Android开发环境（Android studio）
<!--more-->
# 模块开发入门

## 添加Xposed API依赖
> app/build.gradle中添加XposedAPI依赖,使用compileOnly,并同步gradle
``` java
dependencies {
    implementation fileTree(dir: 'libs', include: ['*.jar'])
    implementation 'com.android.support:appcompat-v7:28.0.0'
    testImplementation 'junit:junit:4.12'
    androidTestImplementation 'com.android.support.test:runner:1.0.2'
    androidTestImplementation 'com.android.support.test.espresso:espresso-core:3.0.2'
    compileOnly 'de.robv.android.xposed:api:82'
    compileOnly 'de.robv.android.xposed:api:82:sources'
}
```
## 配置meta-data
> 在AndroidManifest.xml中配置Xposed信息
+ xposedmodule：表明是Xposed模块
+ xposeddescription：Xposed模块描述最好是简单介绍这个模块的功能
+ xposedminversion：表示Xposed最低版本
```XML
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme" >
        <meta-data
            android:name="xposedmodule"
            android:value="true" />
        <meta-data
            android:name="xposeddescription"
            android:value="test" />
        <meta-data
            android:name="xposedminversion"
            android:value="82" />
    </application>
</manifest>
```
## 实现IXposedHookLoadPackage接口

```java
package com.example.test;

import android.app.Activity;
import android.app.AndroidAppHelper;
import android.app.Application;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.widget.Toast;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class main implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {
        //对Activity类的onCreate进行hook
        XposedHelpers.findAndHookMethod(Activity.class, "onCreate", Bundle.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                //Hook函数执行之前进行操作
            }
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                //Hook函数执行之后操作
            }
        });
    }
}
```
## 配置assets/xposed_init
> 鼠标右击模块->New->Folder->Assets Folder即可创建。在assets目录中创建名称为xposed_init的文件，并写入刚刚创建的Xposed模块入口类的全限定类名com.example.test.main。

## 安装并使用
- setting->Build,Execution,Deployment->Instant Run把钩取消掉
- 安装apk
- xposed里勾选模块apk并重启设备
- 现在就已经完成

# API介绍
> 详细API介绍[框架API详细介绍](http://api.xposed.info/reference/packages.html)  
>也可以在AndroidStudio中通过`ctrl+鼠标左键`跳转到相应的源码进行查看，有时候这样会更加方便
## IXposedHookLoadPackage
>这是Xposed的回调接口，Xposed会自动注册这个接口的实现类(在assets/xposed_init文件中配置)为插件代码的执行入口。这是代码注入的入口。每一个DVM进程启动时，都会调用其实现类的handleLoadPackage(LoadPackageParam)方法，并将当前进程的应用程序信息作为参数传递给自定义代码，从而实现代码注入。插件注入的任何功能实现都是从这里开始执行，而不是从插件应用的Application#onCreate()方法开始的。
## XC_LoadPackage.LoadPackageParam
> 封装了正在加载的进程的应用信息。有下面几个变量

- String packageName：The name of the package being loaded.被加载的包名
- String processName：The process in which the package is executed.
- ClassLoader classLoader：The ClassLoader used for this package.
- ApplicationInfo appInfo：More information about the application being loaded
- bool isFirstApplication：if this is the first (and main) application for this process.
## XC_MethodHook
```java
/** 该方法中的代码会在目标方法被调用前执行 **/
protected void beforeHookedMethod(MethodHookParam param) throws Throwable {}

/** 该方法中的代码会在目标方法被调用后执行 **/
protected void afterHookedMethod(MethodHookParam param) throws Throwable {}
```
## MethodHookParam
> XC_MethodHook的参数  

- args：方法的ava方法（Java构造器）参数列表
- method：目标方法，Java方法（Java构造器）对象
- getResult()：获得Java方法的返回值；一般在afterHookedMethod中使用
- setResult(Object result)：修改方法的返回值
## XposedHelpers类
> 源码注释：Helpers that simplify hooking and calling methods/constructors, getting and settings fields。可以获取类，hook和调用方法，设置和获取属性值。下面是常用的4个方法，前两个用来hook java方法，后两个用来hook构造函数

```java
public static XC_MethodHook.Unhook findAndHookMethod(Class<?> clazz, String methodName, Object... parameterTypesAndCallback);
public static XC_MethodHook.Unhook findAndHookMethod(String className, ClassLoader classLoader, String methodName, Object... parameterTypesAndCallback);
public static XC_MethodHook.Unhook findAndHookConstructor(Class<?> clazz, Object... parameterTypesAndCallback);
public static XC_MethodHook.Unhook findAndHookConstructor(String className, ClassLoader classLoader, Object... parameterTypesAndCallback);
```
- clazz：目标方法的类
- className：全限定类名
- methodName: 目标方法名
- Object...：参数列表
- classLoader：指定类加载器，期望从中查找名称为className的类 
- parameterTypesAndCallback：回调函数主要实现beforeHookedMethod和afterHookedMethod
# hook Multidex 和动态加载的解决方法
- 1.首先HookApplication.class的attach。
- 2.然后Hook目标方法。
```java
findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
    @Override
    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
        findAndHookMethod("com.example.test.xxxx", lpparam.classLoader, "methodName", Context.class, new XC_MethodHook() {
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            XposedBridge.log("hook success");
        }
        });
    }
});
```
# 参考链接
- [微信公众号Xposed框架](https://mp.weixin.qq.com/s/4-6fNOLEZbu80JVSgHcPSg "Xposed框架")
- [Xposed官方教程](https://github.com/rovo89/XposedBridge/wiki/ "Xposed官方教程")
- [框架API详细介绍](http://api.xposed.info/reference/packages.html)
