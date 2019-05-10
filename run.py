from flask import Flask, request, make_response, jsonify, url_for, views
from flask_cors import CORS
import json
import jenkins
from jenkins import JenkinsException
from urllib.parse import urlencode
from urllib import request as url_request
from urllib import error
import gitlab
from pyquery import PyQuery

app = Flask(__name__)
CORS(app, supports_credentials=True)


private_token = {"PRIVATE-TOKEN": "PRIVATE-TOKEN"}
gitlab_Url = "http://gitlab.domain/api/v4/projects"
token = "gitlabToken"
fd_token = "jenkins触发器token"
java_token = "jenkins触发器token"


#判断类型，可以让前端直接传参
def check_app_type(app_name):
	if app_name.find('.com') == -1:
		return 'Java'
	else:
		return 'React'

#获取git项目的id
def get_project_id(app_name, giturl):
	final_url = url_request.Request(gitlab_Url + "?search=" + app_name, headers=private_token)
	html = url_request.urlopen(final_url)
	data = json.loads(html.read())
	for dict in data:
		if dict['http_url_to_repo'] == giturl:
			app.logger.info("获取到该项目的git--id {}".format(dict['id']))
			return dict['id']
	return False

#检查构建hook是否已经存在
def check_hook_exist(project_id, url):
	req = url_request.Request(gitlab_Url + "/{}/hooks".format(project_id), headers=private_token)
	html = url_request.urlopen(req).read()
	for data in json.loads(html):
		if data['url'] == url:
			return True
	return False

def get_hook_id(project_id):
	hook_id = []
	req = url_request.Request(gitlab_Url + "/{}/hooks".format(project_id), headers=private_token)
	html = url_request.urlopen(req).read()
	for data in json.loads(html):
		hook_id.append(data['id'])
	return hook_id

#创建构建hook
def create_project_hook(app_name, env, giturl, type):
	add_webhook_data = {}
	add_webhook_data['enable_ssl_verification'] = 'true'
	if type == 'Java':
		project_name = app_name
		url = "http://jenkins_domain/project/" + env + "-" + project_name
		add_webhook_data['token'] = java_token
	else:
		project_name = app_name.split('.')[0]
		add_webhook_data['token'] = fd_token
		if env == 'uat':
			job_name = app_name
		else:
			job_name = project_name + '.' + env + '.test.com'
		url = "http://jenkins_domain/project/" + job_name
	project_id = get_project_id(project_name, giturl)
	add_webhook_data['id'] = project_id
	if check_hook_exist(project_id, url):
		app.logger.info('project {} hook {} already exist'.format(app_name, url))
	else:
		add_webhook_data['url'] = url
		req = url_request.Request(gitlab_Url + "/{}/hooks".format(project_id),
								urlencode(add_webhook_data).encode(), 
								headers=private_token)
	#		print(app_name, project_id)
		try:
			html = url_request.urlopen(req)
			final_code = html.read()
			print('create code return {}'.format(html.getcode()))
			if html.getcode() == 201:
				app.logger.info("添加-- {} --的hook成功".format(app_name))
				return True

		except error.HTTPError as e:
			app.logger.error(e)
			return False
	return True

def delete_project_hook(app_name, env, giturl, type):
	if type == 'Java':
		project_name = app_name
	else:
		project_name = app_name.split('.')[0]
	project_id = get_project_id(project_name, giturl)
	hook_id_list = get_hook_id(project_id)
	for hook_id in hook_id_list:
		req = url_request.Request(gitlab_Url + "/{}/hooks/{}".format(project_id, hook_id),
								headers=private_token)
		req.get_method = lambda: 'DELETE'
		try:
			html = url_request.urlopen(req)
		except error.HTTPError as e:
			app.logger.error(e)
			return False
	return True


#获取项目分支{dev,test,demo,master}
def get_branch(app_name, giturl):
	data = {}
	type = check_app_type(app_name)
	if type == 'Java':
		job_name = 'dev-{}'.format(app_name)
		git_project_name = app_name
	else:
		job_name = app_name.split('.')[0] + '.dev.test.com'
		git_project_name = app_name.split('.')[0]
	try:
		project_id = get_project_id(git_project_name, giturl)
		project_info = gl.projects.get(project_id)
		branches = project_info.branches.list()
	except Exception as e:
		dat['status'] = 500
		data['msg'] = e
		data['branches'] = ''
	else:
		list = []
		for branche in branches:
			list.append(branche.name)
		data['status'] = 200
		data['msg'] = 'Sucess'
		data['branches'] = list
	return data


def commit_file(filename, content, message, operate='create'):
'''
这里写死了project_id
可以根据上面的函数获取对应project_id
'''
	try:
		gl = gitlab.Gitlab("http://gitlab.domain", token)
		project = gl.projects.get(553)
		data = {
			'branch': 'master',
			'commit_message': message,
			'actions': [
				{'action': operate,
				'file_path': filename,
				'content': content
				}]
	}
		project.commits.create(data)
	except:
		return False
	else:
		return True

def get_job_name(app_name, env, type):
	if type == 'Java':
		job_name = '{}-{}'.format(env, app_name)
	elif env == 'uat':
		job_name = app_name
	else:
		job_name = app_name.split('.')[0] + '.' + env + '.test.com'
	return job_name

#获取创建job的xml内容
def make_config_file(app_name, env, giturl, type, server):
	if type == 'Java':
		template_job = 'templates-{}-compile'.format(env)
	else:
		template_job = 'templates-{}-npm'.format(env)
	template_content = server.get_job_config(template_job)
	git_content = "<url>{}</url>\n".format(giturl)
	git_pos = template_content.find("</hudson.plugins.git.UserRemoteConfig>")
	if git_pos != -1:
		xml_content = template_content[:git_pos] + git_content + template_content[git_pos:]
	return xml_content


#Jenkins创建新job
def create_new_job(app_name, env, giturl, type, server):
	data = {}
	git_msg = ''
	xml = make_config_file(app_name, env, giturl, type, server)
	job_name = get_job_name(app_name, env, type)
	if server.job_exists(job_name):
		jenkins_rsp = 'jenkins job {} already exist'.format(job_name)
		status = '200'
		error_msg = 'skip'
		data["jenkins_rsp"] = jenkins_rsp
		data["status"] = status
		data["error_msg"] = error_msg
		return data
	try:
		server.create_job(job_name, xml)
		jenkins_rsp = 'jenkins job create success'
	except Exception as e:
		app.logger.error(e)
		jenkins_rsp = 'jenkins job create failed'
		status = 500
		error_msg = 'jenkins error'
	else:
		status = 200
		error_msg = 'null'
	data["jenkins_rsp"] = jenkins_rsp
	data["status"] = status
	data["error_msg"] = error_msg
			
	return data

def get_url(job_name, server):
	xml = server.get_job_config(job_name)
	giturl = PyQuery(xml.encode('utf-8'))('url').text()
	return giturl


@app.route('/api/CreateJob', methods = ['POST'])
def create():
	server = jenkins.Jenkins('http://jenkens_domain', username='username', password='password')
	results = {}
	envs = ['dev', 'test', 'demo', 'uat']
	app_name = request.json['app_name']
	giturl = request.json['giturl']
	type = check_app_type(app_name)
	for env in envs:
		results[env] = create_new_job(app_name, env, giturl, type, server)
		app.logger.info('start create project {} hooks'.format(app_name))
		try:
			create_project_hook(app_name, env, giturl, type)
		except Exception as e:
			app.logger.error(e)

	return jsonify(results)

@app.route('/api/DeleteJob/', methods = ['POST'])
def delete():
	server = jenkins.Jenkins('http://jenkens_domain', username='username', password='password')
	results = {}
	giturl = ''
	envs = ['dev', 'test', 'demo', 'uat']
	app_name = request.json['app_name']
	type = check_app_type(app_name)
	for env in envs:
		job_name = get_job_name(app_name, env, type)
		try:
			giturl = get_url(job_name, server)
			if server.job_exists(job_name):
				server.delete_job(job_name)
			else:
				pass
			status = 200
			msg = 'delete success'
		except:
			status = 404
			msg = '该项目不存在job，请勿重复删除'
	try:
		delete_project_hook(app_name, env, giturl, type)
	except error.HTTPError as e:
		app.logger.info(e)
	return jsonify({'msg':msg,'status':status})

@app.route('/api/JCSout/<app_name>', methods = ['GET'])
def get_consoleout(app_name):
	server = jenkins.Jenkins('http://jenkens_domain', username='username', password='password')
	data = {}
	try:
		last_build_info = server.get_job_info(app_name)
		last_build_number = last_build_info['lastBuild']['number']
		data['results'] = server.get_build_console_output(app_name, last_build_number)
		data['status'] = 200
	except:
		data['results'] = 'job[{}] last build info does not exist'.format(app_name)
		data['status'] = 500
	print(data)
	return jsonify(data)

	
@app.errorhandler(404)
def not_fount(error):
	return make_response(jsonify({'error': 'Not Found'}), 404)


if __name__ == '__main__':
#	app.run(port = 8888, debug = True)
	app.run(host='0.0.0.0' ,port = 8888, debug = True)

