#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import datetime
from oslo_serialization import jsonutils
import os
import subprocess
import sys


conf = {}
cur_dir = ''
docker_build_dir = None


def parse_json(j_file):
    global conf

    with open(j_file) as json_data:
        conf = jsonutils.load(json_data)
    return


def create_configurator_docker():

    docker_images = cur_dir + '/docker-images/'
    docker_images = os.path.realpath(docker_images)

    # create a docker image
    os.chdir(docker_build_dir)
    # build configuratro docker
    docker_args = ['docker', 'build', '-t', 'configurator-docker', '.']
    ret = subprocess.call(docker_args)
    if(ret):
        print("Failed to build docker image [configurator-docker]")
        return -1

    if not os.path.isdir(docker_images):
        os.mkdir(docker_images)

    os.chdir(docker_images)
    del(docker_args)
    # save the docker image
    docker_args = ['docker', 'save', '-o', 'configurator-docker',
                   'configurator-docker']
    ret = subprocess.call(docker_args)
    if(ret):
        print("Failed to save docker image [configurator-docker]")
        return -1
    # set environment variable, needed by 'extra-data.d'
    os.environ['DOCKER_IMAGES'] = docker_images

    return 0


def dib():

    global docker_build_dir

    dib = conf['dib']
    elems = cur_dir + '/elements/'

    # set the elements path in environment variable
    os.environ['ELEMENTS_PATH'] = elems
    # set the Ubuntu Release for the build in environment variable
    os.environ['DIB_RELEASE'] = conf['ubuntu_release']['release']

    # basic elements
    dib_args = ['disk-image-create', 'base', 'vm', 'ubuntu']
    image_name = conf['ubuntu_release']['release']

    # element for creating configurator image
    if 'nfp-reference-configurator' in dib['elements']:
        image_name = 'nfp_reference_service'
        service_dir = "%s/../../../../contrib/nfp_service/" % cur_dir
        service_dir = os.path.realpath(service_dir)
        pecan_dir = "%s/../../../../nfp/" % cur_dir
        pecan_dir = os.path.realpath(pecan_dir)
        gbpservice_i18n_file = "%s/../../../../_i18n.py" % cur_dir
        os.environ['PECAN_GIT_PATH'] = pecan_dir
        os.environ['SERVICE_GIT_PATH'] = service_dir
        os.environ['GBPSERVICE_I18N_FILE'] = gbpservice_i18n_file
        if 'devuser' in dib['elements']:
            os.environ['DIB_DEV_USER_USERNAME'] = 'ubuntu'
            os.environ['DIB_DEV_USER_SHELL'] = '/bin/bash'
            os.environ['SSH_RSS_KEY'] = (
                "%s/%s" % (cur_dir, image_name))
            os.environ['DIB_DEV_USER_AUTHORIZED_KEYS'] = (
                "%s.pub" % os.environ['SSH_RSS_KEY'])
    elif 'configurator' in dib['elements']:
        if not docker_build_dir:
            docker_build_dir = cur_dir
        if(create_configurator_docker()):
            return (False, None)
        # for bigger size images
        if "--no-tmpfs" not in dib_args:
            dib_args.append('--no-tmpfs')
        # append docker-opt element
        if "docker-opt" not in dib_args:
            dib_args.append("docker-opt")

    for element in dib['elements']:
        image_name = image_name + '_' + element
        dib_args.append(element)

    # offline mode, assuming the image cache (tar) already exists
    if(dib['offline']):
        dib_args.append('--offline')
    # root login enabled, set password environment varaible
    if 'root-passwd' in dib['elements']:
        os.environ['DIB_PASSWORD'] = dib['root_pswd']
    # set the image build cache dir
    dib_args.append('--image-cache')
    dib_args.append(dib['cache_dir'])
    # set image size
    dib_args.append('--image-size')
    dib_args.append(str(dib['image_size']))
    timestamp = datetime.datetime.now().strftime('%I%M%p-%d-%m-%Y')
    image_name = image_name + '_' + timestamp
    dib_args.append('-o')
    if 'nfp-reference-configurator' in dib['elements']:
        image_name = 'nfp_reference_service'
    dib_args.append(str(image_name))

    # wily support is removed from ubuntu 'current' release,
    # download/copy to loation as expected by diskimage-builder
    if conf['ubuntu_release']['release'] == "wily":
        import commands
        commands.getoutput("mkdir -p %s" % dib['cache_dir'])
        wily_SHA256SUMS = "%s/SHA256SUMS.ubuntu.wily.amd64" % dib['cache_dir']
        if not os.path.isfile(wily_SHA256SUMS):
            ret = subprocess.call(["wget", "http://cloud-images-archive.ubuntu.com/releases/wily/release-20160715/SHA1SUMS", "-r", "-O", wily_SHA256SUMS])
            if ret:
                print "ERROR: failed to download ubuntu wily image SHA256SUMS"
                return
        if ((not os.path.isfile(dib['cache_dir'] + '/wily-server-cloudimg-amd64-root.tar.gz')) or (not dib['offline'])):
            # wget the tar file and SHASUM file and save to dib['cache_dir']
            wily_image = "%s/wily-server-cloudimg-amd64-root.tar.gz" % dib['cache_dir']
            ret = subprocess.call(["wget", "http://cloud-images-archive.ubuntu.com/releases/wily/release-20160715/ubuntu-15.10-server-cloudimg-amd64-root.tar.gz", "-r", "-O", wily_image])
            if ret:
                print "ERROR: failed to download ubuntu wily image"
                return

    os.chdir(cur_dir)
    out_dir = 'output'
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    os.chdir(out_dir)
    print("DIB-ARGS: ", dib_args)
    ret = subprocess.call(dib_args)
    if not ret:
        output_path = os.path.realpath('./')
        print("Output path: ", output_path)
        output_image = output_path + '/' + image_name + '.qcow2'

        print("Image location: %s" % output_image)
        with open("%s/last_built_image_path" % output_path, "w") as f:
            f.write(output_image)

        return (True, output_image)

    return (False, None)
