#!/bin/bash

check_group_status(){
    ptg_name=$1
    timeout=$2
    curr_time=0
    while [ $curr_time -lt $timeout ];
    do
        ptg_status=$(gbp group-show $ptg_name | grep -w 'status' | awk '{print $4}')
        if [ 'ACTIVE' == $ptg_status ];then
            echo "group $ptg_name becomes ACTIVE after $curr_time secs"
            break
        elif [ 'ERROR' == $ptg_status ];then
            echo "group $ptg_name went to ERROR state after $curr_time secs"
            break
        fi
        sleep 5
        curr_time=$((curr_time + 5))
    done
}
