#!/bin/bash
printf "\nWelcome to GBP Functional & Negative Test Suite\n"
echo Starting Tests `date`
sudo rm -f test_results.txt
#rc_loc=$(sudo find / -name openrc)
#echo $rc_loc
#source $rc_loc admin admin
FILES=$(<func_neg)
for f in $FILES
do
     if [[ "$f" == "#"* ]]; then
         echo "Skipping $f"
     else
         echo "GOING TO RUN TESTCASE == $f"
         #python $f &>>gbpteststdout
         sudo python $f
         ret=$?
         echo "STATUS === $ret"
     fi
done
printf "\n!!!!! GBP FUNCTIONAL and NEGATIVE TEST SUITE RUN HAS COMPLETED !!!!!\n"
printf "\n######### FINAL RESULTS AFTER THE COMPLETE RUN OF SUITE IS BELOW : #########\n"
NUMBER_OF_TC=$(grep -r TESTCASE_GBP_ test_results.txt | wc -l)
PASSED=$(grep -r PASSED test_results.txt | wc -l)
FAILED=$(grep -r FAILED test_results.txt | wc -l)
printf "\nTotal Number of TestCases Executed= ${NUMBER_OF_TC}\n"
printf "\nNumber of Testcases PASSED = ${PASSED}\n"
printf "\nNumber of Testcases FAILED = ${FAILED}\n"
#printf "\nSTDOUT of Suite Run = <Current directory> gbpteststdout.txt\n"
echo  Finised Tests `date`
