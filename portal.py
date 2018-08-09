# -*- coding: utf-8 -*-

import sys
import time
import json
import argparse
from urllib import request, error, parse
from encode import xEncode, b64, hmac_hex, sha1_hex
from encode import bytes2human, sec2human, timestamp2str


def get_challenge(headers, form_data):
    url = 'http://auth4.tsinghua.edu.cn' + '/cgi-bin/get_challenge'
    challenge_form = {}
    challenge_form['username'] = form_data['username']
    challenge_form['ip'] = form_data['ip']
    challenge_form['double_stack'] = 1
    challenge_form['callback'] = 'a'
    logingpostdata = parse.urlencode(challenge_form)
    req = request.Request(url=url + '?' + logingpostdata, headers=headers)
    with request.urlopen(req) as response:
        response = response.read()
        # print(response)
        try:
            response_dict = json.loads(response[2:len(response) - 1])
            if (response_dict['error'] == 'ok'):
                return response_dict['challenge']
            else:
                return None
        except:
            return None


def check_online(headers):
    url = 'http://auth4.tsinghua.edu.cn' + '/rad_user_info.php'
    req = request.Request(url=url, headers=headers)
    online_info = {}
    try:
        response = request.urlopen(req).read().decode('utf-8')
        if len(response) == 0:
            online_info['online'] = 'Not online'
        else:
            info_list = response.split(',')
            online_info['online'] = 'Online'
            online_info['username'] = info_list[0]
            online_info['login_timestamp'] = int(info_list[1])
            online_info['online_time'] = int(info_list[2]) - int(info_list[1])
            online_info['bytes'] = int(info_list[6])
            online_info['monthly_online_time'] = int(info_list[7])
            online_info['ip'] = info_list[8]
            online_info['balance'] = float(info_list[11])
    except error.URLError as e:
        print("URLError: %s" % e.reason)
        online_info['online'] = 'Error'
    except:
        online_info['online'] = 'Error'
    return online_info


def disp_online_info(online_info):
    print('Online status:           ' + online_info['online'])
    if online_info['online'] == 'Online':
        print('Online user:             ' + online_info['username'])
        print('Time of login:           ' + timestamp2str(online_info['login_timestamp']))
        print('Online time:             ' + sec2human(online_info['online_time']))
        print('Monthly online time:     ' + sec2human(online_info['monthly_online_time']))
        print('Online IP:               ' + online_info['ip'])
        print('IPv4 uasge:              ' + bytes2human(online_info['bytes']))
        print('Account balance:         ' + str(online_info['balance']))


def do_login(headers, form_data):
    url = 'http://auth4.tsinghua.edu.cn' + '/cgi-bin/srun_portal'
    enc = "s" + "run" + "_bx1"
    login_form = {}
    login_form['callback'] = 'a'
    login_form['action'] = 'login'
    login_form['username'] = form_data['username']
    login_form['password'] = form_data['password']
    login_form['ip'] = form_data['ip']
    login_form['ac_id'] = form_data['ac_id']
    login_form['double_stack'] = 1
    login_form['n'] = 200
    login_form['type'] = 1

    token = get_challenge(headers, form_data)
    while token == None:
        token = get_challenge(headers, form_data)
        time.sleep(30)

    json_str = '{"username":"' + login_form['username'] + '","password":"' + login_form['password'] + \
        '","ip":"' + login_form['ip'] + '","acid":"' + \
        login_form['ac_id'] + '","enc_ver":"' + enc + '"}'
    login_form['info'] = '{SRBX1}' + b64(xEncode(json_str, token))
    hmd5 = hmac_hex(token, login_form['password'])
    login_form['password'] = '{MD5}' + hmd5
    login_form['chksum'] = sha1_hex(token + login_form['username'] + token + hmd5 + token + login_form['ac_id'] + token +
                                    login_form['ip'] + token + str(login_form['n']) + token + str(login_form['type']) + token + login_form['info'])

    logingpostdata = parse.urlencode(login_form)
    req = request.Request(url=url + '?' + logingpostdata, headers=headers)
    try:
        response = request.urlopen(req).read()
        # print(response.decode('utf-8'))
        response_dict = json.loads(response[2:len(response) - 1])
        if response_dict['error'] != 'ok':
            print(response_dict['res'] + (': ' + response_dict['error_msg'] if 'error_msg' in response_dict else ': detailed error not specified by server'))
            return 0
        # elif response_dict['suc_msg'] != 'login_ok':
        #     print(response_dict['suc_msg'] + (': ' + response_dict['ploy_msg'] if 'ploy_msg' in response_dict else ': detailed error not specified by server'))
        #     return False
        else:
            return 1
    except error.URLError as e:
        print("URLError: %s" % e.reason)
        return -1
    except:
        print('Unknown error')
        return -1


def do_logout(headers, form_data):
    url = 'http://auth4.tsinghua.edu.cn' + '/cgi-bin/srun_portal'
    enc = "s" + "run" + "_bx1"
    login_form = {}
    login_form['callback'] = 'a'
    login_form['action'] = 'logout'
    login_form['username'] = form_data['username']
    login_form['ip'] = form_data['ip']
    login_form['ac_id'] = form_data['ac_id']
    login_form['double_stack'] = 1
    login_form['n'] = 200
    login_form['type'] = 1

    token = get_challenge(headers, form_data)
    while token == None:
        token = get_challenge(headers, form_data)
        time.sleep(30)

    json_str = '{"username":"' + login_form['username'] + '","ip":"' + login_form['ip'] + '","acid":"' + \
        login_form['ac_id'] + '","enc_ver":"' + enc + '"}'
    login_form['info'] = '{SRBX1}' + b64(xEncode(json_str, token))
    login_form['chksum'] = sha1_hex(token + login_form['username'] + token + login_form['ac_id'] + token +
                                    login_form['ip'] + token + str(login_form['n']) + token + str(login_form['type']) + token + login_form['info'])

    logingpostdata = parse.urlencode(login_form)
    req = request.Request(url=url + '?' + logingpostdata, headers=headers)
    try:
        response = request.urlopen(req).read()
        # print(response.decode('utf-8'))
        response_dict = json.loads(response[2:len(response) - 1])
        if response_dict['error'] != 'ok':
            print(response_dict['error'] + ': ' + response_dict['error_msg'])
            return 0
        else:
            return 1
    except error.URLError as e:
        print("URLError: %s" % e.reason)
        return -1
    except:
        print('Unknown error')
        return -1



if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', help='action to choose, default login', default='login', choices=['login', 'logout', 'check_status'])
    parser.add_argument('-u', '--username', help='username of account')
    parser.add_argument('-p', '--password', help='password of account')
    parser.add_argument('-m', '--max-retries', help='number of retries after failure, default 5', type=int, default=5)
    parser.add_argument('-t', '--interval', help='interval of retries in seconds, default 30', type=int, default=30)
    parser.add_argument('-l', '--local-only', help='Tsinghua connections only, without access to the internet', action='store_true')
    parser.add_argument('-f', '--force', help='login/out without checking online status', action='store_true')

    args = parser.parse_args()

    form_data = {}
    form_data['username'] = args.username
    form_data['password'] = args.password
    form_data['ip'] = ''
    form_data['ac_id'] = '1'

    headers = {}
    headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3440.75 Safari/537.36'

    if args.local_only:
        form_data['username'] += '@tsinghua'
    if args.action == 'login' and (args.username == None or args.password == None):
        sys.exit('Error: specify username and password')
    if args.action == 'logout' and args.username == None:
        sys.exit('Error: specify username')

    attempt = 0
    while attempt < args.max_retries:
        print('Attemp %d: %s' % (attempt + 1, args.action))
        if args.action == 'check_status':
            status = check_online(headers)
            if status['online'] != 'Error':
                disp_online_info(status)
                break
        elif args.action == 'login':
            status = check_online(headers)
            if args.force or status['online'] == 'Not online':
                login_status = do_login(headers, form_data)
                if login_status == 1:
                    print('login succeeded')
                    break
                elif login_status == 0:
                    print('login failed')
                    break
            elif status['online'] == 'Online':
                print('Already online')
                break
        elif args.action == 'logout':
            status = check_online(headers)
            if args.force or status['online'] == 'Online':
                print('try logout as %s' % form_data['username'])
                logout_status = do_logout(headers, form_data)
                if (logout_status == 0):
                    print('try logout as %s' % form_data['username'] + '@tsinghua')
                    form_data['username'] += '@tsinghua'
                    logout_status = do_logout(headers, form_data)
                if logout_status == 1:
                    print('logout succeeded')
                    break
                elif logout_status == 0:
                    print('logout failed')
                    break
            elif status['online'] == 'Not online':
                print('Not online')
                break
        time.sleep(args.interval)
        attempt += 1
    
    if attempt == args.max_retries:
        print('Action failed')