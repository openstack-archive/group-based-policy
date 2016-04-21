#! /usr/bin/python

import datetime
import json
import os
import subprocess
import sys


conf = []
cur_dir = ''


def parse_json(j_file):
    global conf

    with open(j_file) as json_data:
        conf = json.load(json_data)
    return


def dib():
    dib = conf['dib']
    elems = cur_dir + '/elements/'

    # set the elements path in environment variable
    os.environ['ELEMENTS_PATH'] = elems
    # set the Ubuntu Release for the build in environment variable
    os.environ['DIB_RELEASE'] = conf['ubuntu_release']['release']

    image_name = conf['ubuntu_release']['release']

    # basic elements
    dib_args = ['disk-image-create', 'base', 'vm', 'ubuntu', 'debs']

    # configures elements
    for element in dib['elements']:
        image_name = image_name + '_' + element
        dib_args.append(element)
        # root login enabled, set password environment varaible
        if element == 'root-passwd':
            os.environ['DIB_PASSWORD'] = dib['root_password']
        if element == 'nfp-reference-configurator':
            # set environment variable, needed by 'extra-data.d'
            service_dir = cur_dir + '/gbpservice/tests/contrib/nfp_service/'
            service_dir = os.path.realpath(service_dir)
            os.environ['SERVICE_GIT_PATH'] = service_dir

    # offline mode, assuming the image cache (tar) already exists
    dib_args.append('--offline')
    cache_path = dib['cache_path'].replace('~', os.environ.get('HOME', '-1'))
    dib_args.append('--image-cache')
    dib_args.append(cache_path)

    dib_args.append('--image-size')
    dib_args.append(str(dib['image_size_in_GB']))
    timestamp = datetime.datetime.now().strftime('%I%M%p-%d-%m-%Y')
    image_name = image_name + '_' + timestamp
    dib_args.append('-o')
    dib_args.append(str(image_name))

    os.chdir(cur_dir)
    out_dir = 'output'
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    os.chdir(out_dir)
    print "DIB-ARGS: ", dib_args
    ret = subprocess.call(dib_args)
    if not ret:
        image_path = os.path.realpath('./') + '/' + image_name
        print "Image location: %s" % image_path
        with open("/tmp/nfp_image_path", "w") as f:
            f.write(image_path)


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print "ERROR: Invalid Usage"
        print "Usage:\n\t%s <json config file>" % sys.argv[0]
        print "\twhere: <json config file> contains all the configuration"
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

    # run Disk Image Builder to create VM image
    dib()
