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

import os
from oslo_serialization import jsonutils
import subprocess
import sys


conf = []
cur_dir = ''


def parse_json(j_file):
    global conf

    with open(j_file) as json_data:
        conf = jsonutils.load(json_data)
    return


def set_nfp_git_branch(nfp_branch_name, configurator_dir):
    Dockerfile_path = configurator_dir + '/Dockerfile'
    cmd = "sudo sed -i \"s/GIT-BRANCH-NAME/%s/g\" %s" % (
               nfp_branch_name.replace('/', '\/'), Dockerfile_path)
    os.system(cmd)


def create_configurator_docker(nfp_branch_name):
    configurator_dir = "%s/../../../contrib/nfp/configurator" % cur_dir
    docker_images = "%s/output/docker_images/" % cur_dir
    if not os.path.exists(docker_images):
        os.makedirs(docker_images)

    # create a docker image
    os.chdir(configurator_dir)
    set_nfp_git_branch(nfp_branch_name, configurator_dir)
    docker_args = ['docker', 'build', '-t', 'configurator-docker', '.']
    ret = subprocess.call(docker_args)
    if(ret):
        print("Failed to build docker image [configurator-docker]")
        return -1

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
    os.environ['DOCKER_IMAGES_PATH'] = docker_images

    return 0


def dib(nfp_branch_name):
    dib = conf['dib']
    elems = "%s/elements/" % cur_dir

    # set the elements path in environment variable
    os.environ['ELEMENTS_PATH'] = elems
    # set the Ubuntu Release for the build in environment variable
    os.environ['DIB_RELEASE'] = conf['ubuntu_release']['release']

    # basic elements
    dib_args = ['disk-image-create', 'base', 'vm', 'ubuntu']

    # configures elements
    for element in dib['elements']:
        dib_args.append(element)
        # root login enabled, set password environment varaible
        if element == 'root-passwd':
            os.environ['DIB_PASSWORD'] = dib['root_password']
        elif element == 'devuser':
            os.environ['DIB_DEV_USER_USERNAME'] = 'ubuntu'
            os.environ['DIB_DEV_USER_SHELL'] = '/bin/bash'
        elif element == 'nfp-reference-configurator':
            image_name = 'nfp_reference_service'
            service_dir = "%s/../nfp_service/" % cur_dir
            pecan_dir = os.path.abspath(os.path.join(cur_dir,
                                                     '../../../nfp'))
            service_dir = os.path.realpath(service_dir)
            pecan_dir = os.path.realpath(pecan_dir)
            os.environ['PECAN_GIT_PATH'] = pecan_dir
            os.environ['SERVICE_GIT_PATH'] = service_dir
            if 'devuser' in dib['elements']:
                os.environ['SSH_RSS_KEY'] = (
                    "%s/output/%s" % (cur_dir, image_name))
                os.environ['DIB_DEV_USER_AUTHORIZED_KEYS'] = (
                    "%s.pub" % os.environ['SSH_RSS_KEY'])
        elif element == 'configurator':
            image_name = 'configurator'
            create_configurator_docker(nfp_branch_name)
            # for bigger size images
            dib_args.append('--no-tmpfs')

    # offline mode, assuming the image cache (tar) already exists
    dib_args.append('--offline')
    cache_path = dib['cache_path'].replace('~', os.environ.get('HOME', '-1'))
    dib_args.append('--image-cache')
    dib_args.append(cache_path)

    dib_args.append('--image-size')
    dib_args.append(str(dib['image_size_in_GB']))
    dib_args.append('-o')
    dib_args.append(str(image_name))

    os.chdir(cur_dir)
    out_dir = 'output'
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    os.chdir(out_dir)
    print("DIB-ARGS: %r" % dib_args)

    ret = subprocess.call(dib_args)
    if not ret:
        image_path = "%s/output/%s.qcow2" % (cur_dir, image_name)
        print("Image location: %s" % image_path)
        with open("%s/output/last_built_image_path" % cur_dir, "w") as f:
            f.write(image_path)


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("ERROR: Invalid Usage")
        print("Usage:\n\t%s <json config file> [NFP_BRANCH_NAME]"
              % sys.argv[0])
        print("\twhere: <json config file> contains all the configuration")
        print("\tand NFP_BRANCH_NAME is the string, and is optional.")
        exit()

    # save PWD
    cur_dir = os.path.dirname(__file__)
    cur_dir = os.path.realpath(cur_dir)
    if not cur_dir:
        # if script is executed from current dir, get abs path
        cur_dir = os.path.realpath('./')

    # parse args from json file
    parse_json(sys.argv[1])
    elements = conf['dib']['elements']

    nfp_branch_name = sys.argv[2] if len(sys.argv) == 3 else None

    if 'configurator' in elements and nfp_branch_name is None:
        print("ERROR: You have to pass NFP_BRANCH_NAME.")
        exit()

    # run Disk Image Builder to create VM image
    dib(nfp_branch_name)
