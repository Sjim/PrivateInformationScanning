from django.shortcuts import *
from cmdb.views.dao import userInfoDao, userGroupDao
from utils.JsonResponse import JsonResponse
import hashlib
from utils.UserSession import checkUserSession


#: 作用: 添加用户
#: url: userInfo/setFromUserInfo
#: 参数: email, phone, userName, password
def setFromUserInfo(request):
    code, data, message = None, None, None
    try:
        email = request.GET.get('email')
        phone = request.GET.get('phone')
        userName = request.GET.get('userName')
        password = request.GET.get('passWord')
        if email and phone and userName and password:
            if userName == 'admin':
                raise Exception('参数报错: 不能注册管理员账号！')
            userInfo = userInfoDao.getFromUserInfoByLogin(phone)
            if userInfo:
                raise Exception("注册失败,手机号码已存在")
            userInfo = userInfoDao.getFromUserInfoByLogin(email)
            if userInfo:
                raise Exception("注册失败,邮箱已存在")
            h = hashlib.sha256()
            h.update(bytes(password, encoding='utf-8'))
            password = h.hexdigest()
            userGroup = userGroupDao.getAllFromUserGroupByGroupName('员工部')
            userInfoDao.setFromUserInfo(email, phone, userName, password, userGroup.group_id)
            code, message = 200, '账号注册成功'
        else:
            raise Exception('参数报错: 邮箱, 手机号码, 用户名, 密码 都不能为空!')
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=None).getJson())


#: 作用: 修改用户信息-个人用户使用
#: url: userInfo/updInfoFromUserInfo
#: 参数: userName, password
def updInfoFromUserInfo(request):
    code, data, message = None, None, None
    try:
        userInfo = checkUserSession(request)
        userName = request.GET.get('userName')
        phone = request.GET.get('phone')
        email = request.GET.get('email')
        if userName:
            if phone:
                checkUserInfo = userInfoDao.getFromUserInfoByLogin(phone)
                if checkUserInfo and checkUserInfo.user_id != userInfo['user_id']:
                    raise Exception("参数报错: 手机号码已存在")
            if email:
                checkUserInfo = userInfoDao.getFromUserInfoByLogin(phone)
                if checkUserInfo and checkUserInfo.user_id != userInfo['user_id']:
                    raise Exception("参数报错: 邮箱已存在")
            userInfoDao.updAllFromUserInfoByUserId(userInfo['user_id'], userName=userName, phone=phone, email=email)
            code, message = 200, '信息更新成功'
        else:
            raise Exception('参数报错: 用户名不能修改为空！')
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=None).getJson())


#: 作用: 修改用户密码-个人用户使用
#: url: userInfo/updPassWordFromUserInfo
#: 参数: oldPassWrod, newPassWord
def updPassWordFromUserInfo(request):
    code, data, message = None, None, None
    try:
        userInfo = checkUserSession(request)
        oldPassWrod = request.GET.get('oldPassWrod')
        newPassWord = request.GET.get('newPassWord')
        if oldPassWrod and newPassWord:
            #: 密旧码验证
            h = hashlib.sha256()
            h.update(bytes(oldPassWrod, encoding='utf-8'))
            oldPassWrod = h.hexdigest()
            dbPassWord = userInfoDao.getPassWordFromUserInfoByUserId(userInfo['user_id'])
            if oldPassWrod != dbPassWord:
                raise Exception('参数报错: 老密码错误，请重新输入谢谢！')
            #: 新密码更新
            p = hashlib.sha256()
            p.update(bytes(newPassWord, encoding='utf-8'))
            newPassWord = p.hexdigest()
            userInfoDao.updAllFromUserInfoByUserId(userInfo['user_id'], password=newPassWord)
            code, message = 200, '密码修改成功'
        else:
            raise Exception("参数报错: 新旧密码不能为空！")
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=None).getJson())


#: 作用: 登录验证+session
#: url: userInfo/getFromUserInfoByLogin
#: 参数: account, password
def getFromUserInfoByLogin(request):
    code, data, message = None, None, None
    try:
        account = request.GET.get('account')
        password = request.GET.get('password')
        if account and password:
            userInfo = userInfoDao.getFromUserInfoByLogin(account)
            if userInfo:
                if userInfo.state == 2:
                    raise Exception('登录报错: 对不起，您已离职，账号无法再次使用！')
                h = hashlib.sha256()
                h.update(bytes(password, encoding='utf-8'))
                if userInfo.password == h.hexdigest():
                    request.session['userId'] = userInfo.user_id
                    code, data, message = 200, {'userName': userInfo.user_name}, "登录完成"
                else:
                    raise Exception('密码输入错误')
            else:
                raise Exception("用户不存在")
        else:
            raise Exception('参数报错: 登录名与密码不能为空')
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 注销登录
#: url: userInfo/delFromSessionByKey
#: 参数: None
def delFromSessionByKey(request):
    code, data, message = None, None, None
    try:
        del request.session["userId"]
        code, message = 200, '注销完成'
    except Exception as e:
        code, message = 300, '用户没有登录，无需注销'
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 查询指定用户信息-admin用户使用
#: url: userInfo/getAllFromUsreInfoByUserId
#: 参数: userId
def getAllFromUsreInfoByUserId(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        userId = request.GET.get('userId')
        if userId is None:
            raise Exception('参数报错: userId不能为空！')
        userInfo = userInfoDao.getAllFromUsreInfoByUserId(userId)
        code, data = 200, {'userInfo': userInfo}
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 查询全部用户id与用户名
#: url: userInfo/getAllUserInfo
#: 参数: None
def getAllUserInfo(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        groupId = request.GET.get("groupId")
        userInfoList = userInfoDao.getAllUserInfo(groupId=groupId)
        code, data = 200, list(userInfoList)
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 用户信息查询分页功能，模糊查询
#: url: userInfo/getAllFromUserInfoByPage
#: 参数: groupId, userName
def getAllFromUserInfoByPage(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        page = request.GET.get('page')
        groupId = request.GET.get('groupId')
        userName = request.GET.get('userName')
        userInfoList, numPages = userInfoDao.getAllFromUserInfoByPage(page=page, groupId=groupId, userName=userName)
        code = 200
        data = {
            'userInfoList': list(userInfoList),
            'numPages': numPages,
            'page': int(page)
        }
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 查询个人用户信息
#: url: userInfo/getAllFromUsreInfoByMyself
#: 参数: userId
def getAllFromUsreInfoByMyself(request):
    code, data, message = None, None, None
    try:
        userInfo = checkUserSession(request)
        userInfo = userInfoDao.getAllFromUsreInfoByUserId(userInfo['user_id'])
        code, data = 200, {'userInfo': userInfo}
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 重置用户密码-管理员使用
#: url: userInfo/updPassWordFromUserInfoByUserId
#: 参数: userId, password
def updPassWordFromUserInfoByUserId(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        userId = request.GET.get('userId')
        password = request.GET.get('password')
        if userId and password:
            h = hashlib.sha256()
            h.update(bytes(password, encoding='utf-8'))
            password = h.hexdigest()
            userInfoDao.updAllFromUserInfoByUserId(userId, password=password)
            code, message = 200, '重置密码成功'
        else:
            raise Exception("参数报错: userId与password 都不能为空！")
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=None).getJson())


#: 作用: 修改用户分组-管理员使用
#: url: userInfo/updGroupFromUserInfoByUserId
#: 参数: userId, password
def updGroupFromUserInfoByUserId(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        userId = request.GET.get('userId')
        groupId = request.GET.get('groupId')
        state = request.GET.get('state')
        if userId:
            userInfoDao.updAllFromUserInfoByUserId(userId, groupId=groupId, state=state)
            code, message = 200, '修改用户信息完成'
        else:
            raise Exception("参数报错: userId 不能为空！")
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=None).getJson())

#: 作用: 添加vlan
#: url: vlan/setFromVlan
#: 参数: vlanName, gateway, network
def setFromVlan(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        vlanName = requset.GET.get('vlanName')
        gateway = requset.GET.get('gateway')
        network = requset.GET.get('network')
        if vlanName and gateway and network:
            vlanInfo = vlanDao.getAllFromVlanByVlanName(vlanName)
            if vlanInfo != None:
                raise Exception("vlan名已存在，请修改vlan名！")
            vlanDao.setFromVlan(vlanName, gateway, network)
            code, message = 200, '添加成功'
        else:
            raise Exception('参数报错: vlanName, gateway, network 都不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 删除vlan
#: url: vlan/delFromVlanById
#: 参数: id
def delFromVlanById(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        id= requset.GET.get('id')
        if id and id.isdigit():
            vlanDao.delFromVlanById(id)
            code, message = 200, '删除成功'
        else:
            raise Exception('参数报错： id不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 查看分页vlan
#: url: vlan/getAllFromVlanByPage
#: 参数: page, vlanName
def getAllFromVlanByPage(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        page = requset.GET.get('page')
        vlanName = requset.GET.get('vlanName')
        if page:
            vlanList, numPages = vlanDao.getAllFromVlanByPage(page=page, vlanName=vlanName)
            code = 200
            data = {
                'vlanList': OrmConversion(list(vlanList)),
                'numPages': numPages,
                'page': int(page)
            }
        else:
            raise Exception('参数报错: page不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 更新vlan信息
#: url: vlan/updAllFromVlanById
#: 参数: id, vlanName, gateway, network
def updAllFromVlanById(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        id = requset.GET.get('id')
        vlanName = requset.GET.get('vlanName')
        gateway = requset.GET.get('gateway')
        network = requset.GET.get('network')
        if id and id.isdigit():
            vlanDao.updAllFromVlanById(id, vlanName=vlanName, gateway=gateway, network=network)
            code, message = 200, '更新成功'
        else:
            raise Exception('参数报错： id不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 查看指定vlan信息
#: url: vlan/getAllFromValnById
#: 参数: id
def getAllFromValnById(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        id = requset.GET.get('id')
        if id and id.isdigit():
            vlanInfo = vlanDao.getAllFromValnById(id)
            code, data = 200, { 'vlan': OrmConversion(vlanInfo) }
        else:
            raise Exception('参数报错： id不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 查看所有vlan信息
#: url: vlan/getIdAndVlanNameFromVlan
#: 参数: None
def getIdAndVlanNameFromVlan(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        vlanList = vlanDao.getIdAndVlanNameFromVlan()
        code, data = 200, {'vlanList': list(vlanList)}
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())

#: 作用: 根据groupId查询查询用户组信息
#: url: userGroup/getAllFromUserGroupByGroupId
#: 参数: groupId
def getAllFromUserGroupByGroupId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        groupId = requset.GET.get('groupId')
        if groupId:
            userGroup = userGroupDao.getAllFromUserGroupByGroupId(groupId)
            code, data = 200, {'userGroup': OrmConversion(userGroup)}
        else:
            raise Exception('参数报错: groupId 不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 添加用户分组信息
#: url: userGroup/setFromUserGroup
#: 参数: groupName, roleId, remarks
def setFromUserGroup(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        groupName = requset.GET.get('groupName')
        roleId = requset.GET.get('roleId')
        remarks = requset.GET.get('remarks')
        if groupName:
            userGroupDao.setFromUserGroup(groupName, roleId, remarks)
            code, message = 200, '添加完成'
        else:
            raise Exception('参数报错: groupName  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())



#: 作用: 根据groupId更新用户信息
#: url: userGroup/updAllFromUserGroupByGroupId
#: 参数: groupId, groupName, roleId, remarks
def updAllFromUserGroupByGroupId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        groupId = requset.GET.get('groupId')
        groupName = requset.GET.get('groupName')
        roleId = requset.GET.get('roleId')
        remarks = requset.GET.get('remarks')
        if groupId:
            userGroupDao.updAllFromUserGroupByGroupId(groupId, groupName=groupName, roleId=roleId, remarks=remarks)
            code, message = 200, '更新完成'
        else:
            raise Exception('参数报错: groupId  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 根据groupId删除角色信息
#: url: userGroup/delFromUserGroupByGroupId
#: 参数: groupId
def delFromUserGroupByGroupId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        groupId = requset.GET.get('groupId')
        if groupId:
            userInfoDao.updGroupIdFromUserInfoByGroupId(groupId)
            userGroupDao.delFromUserGroupByGroupId(groupId)
            code, message = 200, '删除完成'
        else:
            raise Exception('参数报错: groupId  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 用户组分页查询带模糊查询功能
#: url: userGroup/getListFromUserGroupByPage
#: 参数: page, groupName
def getListFromUserGroupByPage(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        page = requset.GET.get('page')
        groupName = requset.GET.get('groupName')
        if page:
            userGroupList, numPages = userGroupDao.getListFromUserGroupByPage(page=page, groupName=groupName)
            code = 200
            data = {
                'userGroupList': list(userGroupList),
                'numPages': numPages,
                'page': int(page)
            }
        else:
            raise Exception('参数报错: page  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 获取所有用户组与用户组Id
#: url: userGroup/getGroupIdAndGroupNameFromUserGroup
#: 参数: groupId
def getGroupIdAndGroupNameFromUserGroup(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        userGroupList = userGroupDao.getGroupIdAndGroupNameFromUserGroup()
        code, data = 200, {'userGroupList': list(userGroupList)}
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 发布工单分页查询，带模糊查询
#: url: releaseOrder/getListFromReleaseOrderByPage
#: 参数: page, orderTitle, status
def getListFromReleaseOrderByPage(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        page = requset.GET.get('page')
        orderTitle = requset.GET.get('orderTitle')
        status = requset.GET.get('status')
        if page:
            releaseOrderList, numPages= releaseOrderDao.getListFromReleaseOrderByPage(page, orderTitle=orderTitle, status=status)
            code = 200
            data = {
                'releaseOrderList': list(releaseOrderList),
                'numPages': numPages,
                'page': int(page)
            }
        else:
            raise Exception('参数报错: page 不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 查询指定orderId的工单信息
#: url: releaseOrder/getAllFromReleaseOrderByOrderId
#: 参数: orderId
def getAllFromReleaseOrderByOrderId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        orderId = requset.GET.get('orderId')
        if orderId:
            releaseOrder = releaseOrderDao.getAllFromReleaseOrderByOrderId(orderId)
            code, data = 200, {'releaseOrder': releaseOrder}
        else:
            raise Exception('参数报错: orderId不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 添加发布工单信息
#: url: releaseOrder/setFromReleaseOrder
#: 参数: orderTitle, orderContent, releaseTime, ambientId, artisanId, authorId, productId, remarks, ftpPath
def setFromReleaseOrder(requset):
    code, data, message = None, None, None
    try:
        userInfo = checkUserSession(requset)
        orderTitle = requset.GET.get('orderTitle')
        orderContent = requset.GET.get('orderContent')
        releaseTime = requset.GET.get('releaseTime')
        executorId = requset.GET.get('executorId')
        ambientId = requset.GET.get('ambientId')
        artisanId = requset.GET.get('artisanId')
        authorId = userInfo['user_id']
        productId = requset.GET.get('productId')
        remarks = requset.GET.get('remarks')
        ftpPath = requset.GET.get('ftpPath')
        if orderTitle and orderContent and releaseTime and ambientId and artisanId and authorId and productId and executorId:
            releaseOrder = releaseOrderDao.setFromReleaseOrder(orderTitle, orderContent, releaseTime, ambientId, executorId,
                                                               artisanId, authorId, productId, remarks=remarks, ftpPath=ftpPath)
            code, message = 200, '添加工单完成'
        else:
            raise Exception('参数报错: orderTitle, orderContent, releaseTime, ambientId, executorId, artisanId, authorId, productId 都不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 删除发布工单信息
#: url: releaseOrder/delFromReleaseOrderByOrderId
#: 参数: orderId
def delFromReleaseOrderByOrderId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        orderId = requset.GET.get('orderId')
        if orderId:
            releaseOrderDao.delFromReleaseOrderByOrderId(orderId)
            code, message = 200, '删除工单完成'
        else:
            raise Exception('参数报错: orderId 不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 指定orderId, 修改工单内容
#: url: releaseOrder/updContentFromReleaseOrdeByOrderId
#: 参数: orderId, orderTitle, orderContent, ambientId, releaseTime, ftpPath, remarks
def updContentFromReleaseOrdeByOrderId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        orderId = requset.GET.get('orderId')
        orderTitle = requset.GET.get('orderTitle')
        orderContent = requset.GET.get('orderContent')
        ambientId = requset.GET.get('ambientId')
        releaseTime = requset.GET.get('releaseTime')
        executorId = requset.GET.get('executorId')
        artisanId = requset.GET.get('artisanId')
        productId = requset.GET.get('productId')
        ftpPath = requset.GET.get('ftpPath')
        remarks = requset.GET.get('remarks')
        if orderId:
            releaseOrderDao.updContentFromReleaseOrdeByOrderId(orderId, orderTitle, orderContent, ambientId, releaseTime,
                                                               executorId, artisanId, productId, ftpPath=ftpPath, remarks=remarks)
            code, message = 200, '更新工单内容成功'
        else:
            raise Exception('参数报错: orderId 不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 指定orderId,修改工单授权
#: url: releaseOrder/updAuthorizerFromReleaseOrdeByOrderId
#: 参数: userId, orderId, authorizer
def updAuthorizerFromReleaseOrdeByOrderId(requset):
    code, data, message = None, None, None
    try:
        userInfo = checkUserSession(requset)
        userId = userInfo['userId']
        orderId = requset.GET.get('orderId')
        authorizer = requset.GET.get('authorizer')
        if userId:
            releaseOrderDao.updAuthorizerFromReleaseOrdeByOrderId(userId, orderId, authorizer)
            code, message = 200, '发布工单授权完成'
        else:
            raise Exception('参数报错: orderId 不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 指定orderId,修改工单状态
#: url: releaseOrder/updStatusFromReleaseOrderByOrderId
#: 参数: orderId, status
def updStatusFromReleaseOrderByOrderId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        orderId = requset.GET.get('orderId')
        status = requset.GET.get('status')
        if orderId and status:
            releaseOrderDao.updStatusFromReleaseOrderByOrderId(orderId, status)
            code, message = 200, '工单状态更新完成'
        else:
            raise Exception('参数报错: orderId, status 都不能为空')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())

#: 作用: 根据roleId查询角色信息
#: url: roleInfo/getAllFromRoleInfoByRoleId
#: 参数: roleId
def getAllFromRoleInfoByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        apiId = requset.GET.get('roleId')
        if apiId:
            roleInfo = roleInfoDao.getAllFromRoleInfoByRoleId(apiId)
            code = 200
            data = {'roleInfo': OrmConversion(roleInfo)}
        else:
            raise Exception('参数报错: roleId 不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 根据roleId查询角色信息与角色权限详情
#: url: roleInfo/getAllFromRoleInfoAndApiInfoByRoleId
#: 参数: roleId
def getAllFromRoleInfoAndApiInfoByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        apiId = requset.GET.get('roleId')
        if apiId:
            roleInfo = roleInfoDao.getAllFromRoleInfoByRoleId(apiId)
            if roleInfo.api_list == '*':
                apiInfoList = apiInfoDao.getAllFromApiInfo()
            elif roleInfo.api_list:
                apiIdList = json.loads(roleInfo.api_list)
                apiInfoList = apiInfoDao.getAllFromApiInfoByApiIdList(apiIdList)
            else:
                apiInfoList = []
            code = 200
            data = {
                'roleInfo': OrmConversion(roleInfo),
                'apiInfoList': OrmConversion(list(apiInfoList))
            }
        else:
            raise Exception('参数报错: roleId 不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 添加角色信息
#: url: roleInfo/setFromRoleInfo
#: 参数: roleName, remarks
def setFromRoleInfo(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        roleName = requset.GET.get('roleName')
        remarks = requset.GET.get('remarks')
        if roleName:
            roleInfoDao.setFromRoleInfo(roleName, remarks)
            code, message = 200, '添加完成'
        else:
            raise Exception('参数报错: roleName  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 根据roleId更新角色信息
#: url: roleInfo/updAllFromRoleInfoByRoleId
#: 参数: roleId, roleName, apiList, remarks
def updAllFromRoleInfoByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        roleId = requset.GET.get('roleId')
        roleName = requset.GET.get('roleName')
        remarks = requset.GET.get('remarks')
        if roleId:
            roleInfoDao.updAllFromRoleInfoByRoleId(roleId, roleName=roleName, remarks=remarks)
            code, message = 200, '更新完成'
        else:
            raise Exception('参数报错: roleId  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())



#: 作用: 根据roleId删除指定角色信息
#: url: roleInfo/delFromRoleInfoByRoleId
#: 参数: roleId
def delFromRoleInfoByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        roleId = requset.GET.get('roleId')
        if roleId:
            userGroupDao.updRoleIdIsNoneFromUserGroupByRoleId(roleId)
            roleInfoDao.delFromRoleInfoByRoleId(roleId)
            code, message = 200, '更新完成'
        else:
            raise Exception('参数报错: apiId  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: roleInfo分页查询带模糊查询功能
#: url: roleInfo/getListFromRoleInfoByPage
#: 参数: page, roleName
def getListFromRoleInfoByPage(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        page = requset.GET.get('page')
        roleName = requset.GET.get('roleName')
        if page:
            roleInfoList, numPages = roleInfoDao.getListFromRoleInfoByPage(page=page, roleName=roleName)
            code = 200
            data = {
                'roleInfoList': OrmConversion(list(roleInfoList)),
                'numPages': numPages,
                'page': int(page)
            }
        else:
            raise Exception('参数报错: page  不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 查询全部角色id与角色名
#: url: roleInfo/getRoleIdAndRoleNameFromRoleInfo
#: 参数: page, roleName
def getRoleIdAndRoleNameFromRoleInfo(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)

        roleInfoList = roleInfoDao.getRoleIdAndRoleNameFromRoleInfo()
        code, data = 200, {'roleInfoList': list(roleInfoList)}
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 根据roleId查询角色信息与角色拥有的权限详情与未拥有的权限详情
#: url: roleInfo/getListFromRoleInfoAndApiInfoByRoleId
#: 参数: roleId
def getListFromRoleInfoAndApiInfoByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        apiId = requset.GET.get('roleId')
        if apiId:
            roleInfo = roleInfoDao.getAllFromRoleInfoByRoleId(apiId)
            if roleInfo.api_list == '*':
                apiInfoList = apiInfoDao.getAllFromApiInfo()
                notApiInfoList = []
            elif roleInfo.api_list:
                apiIdList = json.loads(roleInfo.api_list)
                apiInfoList = apiInfoDao.getAllFromApiInfoByApiIdList(apiIdList)
                notApiInfoList = apiInfoDao.getAllFromApiInfoByNotApiIdList(apiIdList)
            else:
                apiInfoList = []
                notApiInfoList = apiInfoDao.getAllFromApiInfo()
            code = 200
            data = {
                'roleInfo': OrmConversion(roleInfo),
                'apiInfoList': OrmConversion(list(apiInfoList)),
                'notApiInfoList': OrmConversion(list(notApiInfoList))
            }
        else:
            raise Exception('参数报错: roleId 不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 添加角色权限
#: url: roleInfo/addApiListFromRoleIdByRoleId
#: 参数: roleId, apiList
def addApiListFromRoleIdByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        roleId = requset.GET.get('roleId')
        apiList = requset.GET.get('apiList')
        if roleId and apiList:
            roleInfo = roleInfoDao.getAllFromRoleInfoByRoleId(roleId)
            if roleInfo.api_list == '*':
                raise Exception("权限报错: 不能修改admin权限！")
            apiList = json.loads(apiList)
            if roleInfo.api_list and roleInfoDao != 'null':
                dbApiList = json.loads(roleInfo.api_list)
                apiList = list(set(apiList).difference(set(dbApiList)))
                dbApiList.extend(apiList)
            else:
                dbApiList = apiList
            roleInfoDao.updAllFromRoleInfoByRoleId(roleId, apiList=json.dumps(dbApiList))
            code, message = 200, '添加权限完成'
        else:
            raise Exception('参数报错: roleId, apiList 都不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 删除角色权限
#: url: roleInfo/delApiListFromRoleIdByRoleId
#: 参数: roleId, apiList
def delApiListFromRoleIdByRoleId(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        roleId = requset.GET.get('roleId')
        apiList = requset.GET.get('apiList')
        if roleId and apiList:
            roleInfo = roleInfoDao.getAllFromRoleInfoByRoleId(roleId)
            if roleInfo.api_list == '*':
                raise Exception("权限报错: 不能修改admin权限！")
            apiList = json.loads(apiList)
            if roleInfo.api_list:
                dbApiList = json.loads(roleInfo.api_list)
                dbApiList = list(set(dbApiList).difference(set(apiList)))
                roleInfoDao.updAllFromRoleInfoByRoleId(roleId, apiList=json.dumps(dbApiList))
                code, message = 200, '删除权限完成'
            else:
                raise Exception('权限报错: 该角色没有需要删除的权限！')
        else:
            raise Exception('参数报错: roleId, apiList 都不能为空！')
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())

#: 作用: salt收集新主机信息
#: url: salt/setNewHostInfo
#: 参数: saltIdList
def setNewHostInfo(requset):
    code, data, message = None, None, None
    try:
        checkUserSession(requset)
        saltIdList = requset.GET.get('saltIdList')
        if saltIdList:
            saltIdList = json.loads(saltIdList)
            if type(saltIdList) == list:
                hostInfoDao.setSaltHostInfo(saltIdList)
                code, message = 200, "添加完成"
            else:
                 raise Exception("saltIdList转换list类型异常")
        else:
            raise Exception("saltIdList不能为空")
    except Exception as e:
        code, data, message = 300, None, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: salt发现新主机
#: url: salt/getNewSaltId
#: 参数: None
def getNewSaltId(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        newHost = hostInfoDao.getNewSaltId()
        if newHost:
            data = newHost
        else:
            raise Exception("暂无新主机")
        code = 200
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: salt更新全部主机资源
#: url: salt/updAllHostInfoBySalt
#: 参数: hostId
def updAllHostInfoBySalt(request):
    code, data, message = None, None, None
    try:
        # session回话验证
        checkUserSession(request)
        hostId = request.GET.get('hostId')
        if hostId and hostId.isdigit() == False:
            raise Exception('参数报错: hostId必须为整数')
        hostInfoList = hostInfoDao.getSaltIdFromHostInfo(hostId=hostId)
        if len(hostInfoList) == 0:
            raise Exception('主机处于已删除状态，无法更新！')
        # 获取存在的saltId
        saltIdList = [ hostInfo['salt_id'] for hostInfo in hostInfoList ]
        # salt检查主机是否正常
        saltCheckList = saltDao.getSaltTest(saltIdList)
        # 如果不正常更新状态为下线,状态正常添加到主机列表中，进行更新

        for host in hostInfoList:
            if saltCheckList[host['salt_id']] != True:
                saltIdList.remove(host['salt_id'])
                hostInfoDao.updAllHostInfobyHostId(host['host_id'], state=1)

        if hostInfoList is not None:
            # 针对正常主机，获取主机信息，进行更新
            saltGrains = saltDao.getSaltGrains(saltIdList)
            saltSsh = saltDao.getHostSsh(saltIdList)
            saltDisk = saltDao.getSaltDisk(saltIdList)
            saltMem = saltDao.getSaltMem(saltIdList)
            for saltId in saltIdList:
                # 主机详细更新
                hostName = saltGrains[saltId]['nodename']
                aliesName = saltGrains[saltId]['host']
                osFullName = saltGrains[saltId]['osfullname']
                osRelease = saltGrains[saltId]['osrelease']
                kernelRelease = saltGrains[saltId]['kernelrelease']
                cpuModel = saltGrains[saltId]['cpu_model']
                cpusNumber = saltGrains[saltId]['num_cpus']
                hostType = saltGrains[saltId]['virtual']
                sshPort = saltSsh[saltId]
                mem = saltMem[saltId]['MemTotal']['value']
                swap = saltMem[saltId]['SwapTotal']['value']
                hostId = hostInfoDao.updAllHostInfobyHostId(saltId=saltId, hostName=hostName, aliesName=aliesName, memory=None, swap=None,
                                                   osFullname=osFullName, osRelease=osRelease, kernelRelease=kernelRelease,
                                                   cpuModel=cpuModel, cpusNumber=cpusNumber, hostType=hostType, sshPort=sshPort, state=0)
                # 网卡数据更新
                networkDao.delFromNetworkById(hostId)
                for key, values in saltGrains[saltId]['ip4_interfaces'].items():
                    if key == "lo" or len(values) == 0:
                        continue
                    network = networkDao.getFromNetworkByHostId(hostId, key)
                    if network:
                        networkDao.updFromNetworkByHostId(network.id, values[0])
                    else:
                        networkDao.setFromNetworkByHostId(hostId, key, values[0])
                # 磁盘数据更新
                diskInfoDao.delFromDiskInfoByHostId(hostId)
                diskList = saltDisk[saltId].split('\n')
                for diskStr in diskList:
                    diskStrList = diskStr.split(' ')
                    diskInfo = diskInfoDao.getFromDiskInfoById(hostId, diskStrList[1].strip(':'))
                    if diskInfo:
                        diskInfoDao.updFromDiskInfoByHostId(diskInfo.id, diskStrList[2], diskStrList[4])
                    else:
                        diskInfoDao.setFromDiskInfo(hostId, diskStrList[1].strip(':'), diskStrList[2], diskStrList[4])

        code, message = 200, '更新完成'
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 作用: 主机远程批量命令执行
#: url: salt/getCommandFromSaltBySaltIdList
#: 参数: saltIdList, command
def getCommandFromSaltBySaltIdList(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        saltIdList = request.GET.get('saltIdList')
        command = request.GET.get('command')
        if saltIdList is None or command is None or saltIdList == '':
            raise Exception('参数报错: saltIdList, command不能为空！')
        saltIdList = saltIdList.split(',')
        normalSaltIdList = hostInfoDao.getSaltIdListFromHostInfoByState(saltIdList)
        commandResult = {}
        if normalSaltIdList:
            commandResult = saltDao.getCommandFromSaltBySaltIdList(normalSaltIdList, command)
        abnormalsetSaltIdList = list(set(saltIdList) - set(normalSaltIdList))
        for saltId in abnormalsetSaltIdList:
            commandResult[saltId] = 'salt无法连接，请检查主机salt-minion是否正常！'
        code, data = 200, {'commandResult': commandResult}
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())


#: 收集与更新主机项目列表
#: url: salt/getProjectListFromHostInfoBySalt
#: 参数: None
def getProjectListFromHostInfoBySalt(request):
    code, data, message = None, None, None
    try:
        checkUserSession(request)
        hostInfoList = hostInfoDao.getALlFromHostInfoByState()
        projectInfoList = projectInfoDao.getProjectPathProjectNameFromProjectInfo()

        for hostInfo in hostInfoList:
            projectList = []
            for projectInfo in projectInfoList:
                saltResult = saltDao.getCheckFolderFromSaltBysaltIdList(hostInfo['salt_id'], projectInfo['project_path'])
                if saltResult[hostInfo['salt_id']] == True:
                    projectList.append(projectInfo['project_id'])
            hostInfoDao.updProjectListFromHostInfoByHostId(hostInfo['host_id'], json.dumps(projectList))

        code, message= 200, '主机项目一键收集与更新完成'
    except Exception as e:
        code, message = 300, str(e)
    finally:
        return HttpResponse(JsonResponse(code=code, message=message, data=data).getJson())