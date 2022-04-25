#!/bin/bash

export PATH=$PATH:/bin:/usr/bin:/usr/local/bin:/home/ec2-user/.local/bin

if [[ "X${1}" != "X" ]]; then 
    account=$1
    echo "Account ID: ${1}"
fi
if [[ "X${2}" != "X" ]]; then
    reg=$2
    echo "AWS Region: ${2}"
fi
if [[ "X${3}" != "X" ]]; then
    FWIP=$3
    echo "FW Management IP: ${3}"
fi

SECONDS=0

echo "=== Setting up the Environment ==="

terraform --version 2> /dev/null | grep Terraform > /dev/null 2>&1

if [ $? -eq 0 ]

  then

     terraform init > /dev/null

  else

     echo "Configuring Terraform "

     version=$(cat /etc/*release 2> /dev/null| grep ^NAME | cut -d'"' -f2)

         if [ "$version" == Amazon\ Linux ]; then sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo > /dev/null 2>&1; \

                                sudo yum install terraform -y >/dev/null; terraform init >/dev/null; \

         elif [ "$version" == Ubuntu ]; then sudo apt-get update >/dev/null && sudo apt-get install -y gnupg software-properties-common curl >/dev/null; \

                                curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -; \

                                sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main" >/dev/null; \

                                sudo apt-get update >/dev/null && sudo apt-get install terraform >/dev/null; terraform init >/dev/null; \


         else brew install terraform; terraform init; fi


fi

if ! command -v pip3 &> /dev/null

then
    echo "Configuring pip3"
    
    version=$(cat /etc/*release 2> /dev/null| grep ^NAME | cut -d'"' -f2)
    
    if [ "$version" == Ubuntu ]; then sudo apt-get install python3-pip -y >/dev/null; \
    
    elif [ "$version" == Amazon\ Linux ]; then sudo yum install python3-pip -y; fi
    

fi


if ! command -v mssh &> /dev/null

then
    echo "Configuring MSSH"
    
    version=$(cat /etc/*release 2> /dev/null| grep ^NAME | cut -d'"' -f2)
	
    if [ "$version" == Ubuntu ]; then sudo apt-get install mssh -y >/dev/null; else pip3 install ec2instanceconnectcli >/dev/null; fi
    
fi

if ! command -v jq &> /dev/null

then
    echo "Configuring Jq"

    version=$(cat /etc/*release 2> /dev/null| grep ^NAME | cut -d'"' -f2)

    if [ "$version" == Ubuntu ]; then sudo apt-get install jq -y >/dev/null; sudo apt install awscli -y >/dev/null; \

    elif [ "$version" == Amazon\ Linux ]; then sudo yum install jq -y >/dev/null; \

    else brew install jq; fi

fi    

if [[ "X${account}" == "X" ]] && [[ "X${reg}" == "X" ]] && [[ "X${FWIP}" == "X" ]]; then
    echo "Enter Account Details | Region | FW IP to connect"

    echo;read account

    read reg

    read FWIP
fi;

env="prod"
if [[ "X${account}" == "X204785354882" ]] || [[ "X${account}" == "X132143765919" ]]; then
    env="preprod"
fi;

export TF_VAR_region="$reg"
export TF_VAR_env="$env"

## STS role for assuming FWAccess-SSO in Pre-prod-SRE 

if [[ "X$(aws s3 ls --profile AWSReadOnlyAccess-084256098262 || echo "fail")" == "Xfail" ]]; then
    echo "Please Login to aws sso"
    aws sso login --profile AWSReadOnlyAccess-084256098262
fi;

eval $(aws sts assume-role --role-arn arn:aws:iam::084256098262:role/FWAccess-SSO --role-session-name SSOFW --profile AWSReadOnlyAccess-084256098262 | jq -r '.Credentials | "export AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nexport AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nexport AWS_SESSION_TOKEN=\(.SessionToken)\n"')

eval $(aws sts assume-role --role-arn arn:aws:iam::$account:role/FwaasmsshRole --role-session-name FW | jq -r '.Credentials | "export AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nexport AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nexport AWS_SESSION_TOKEN=\(.SessionToken)\n"')

aws configure --profile MSSH set aws_access_key_id $AWS_ACCESS_KEY_ID
aws configure --profile MSSH set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
aws configure --profile MSSH set aws_session_token $AWS_SESSION_TOKEN

terraform apply -auto-approve > /dev/null &

pid=$! # Process Id of the previous running command

spin[0]="-";spin[1]="\\";spin[2]="|";spin[3]="/";echo;echo -n "Connecting to Terminal ......... ${spin[0]}"

while kill -0 $pid 2>/dev/null; do for i in "${spin[@]}"; do echo -ne "\b$i"; sleep 0.1; done; done

IP=$(terraform state show `terraform state list | grep -i aws_instance` | grep "\public_ip\b"  | cut -d"=" -f2-  | tr -d '"')

Instanceid=$(terraform state show `terraform state list | grep -i aws_instance` | grep id | cut -d"=" -f2- | head -1 | tr -d '"')

Region=$(terraform state show `terraform state list | grep -i aws_instance` | grep availability_zone | cut -d"=" -f2- | tr -d '"' | rev | cut -c2- | rev)

AZ=$(terraform state show `terraform state list | grep -i aws_instance` | grep availability_zone | cut -d"=" -f2- | tr -d '"')

## Creating one-time pub key ##

mkdir -p /tmp/mssh/.ssh; chmod 700 /tmp/mssh/.ssh; ssh-keygen -q -t rsa -N '' -f /tmp/mssh/.ssh/id_rsa <<<y 2>&1 >/dev/null
 
echo;echo "Pushing Onetime Configuration "

echo;aws ec2-instance-connect send-ssh-public-key --region $Region --instance-id $Instanceid --availability-zone $AZ --instance-os-user ec2-user --ssh-public-key file:///tmp/mssh/.ssh/id_rsa.pub --profile MSSH --output text >/dev/null

duration=$SECONDS;echo;echo "$(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed for connecting !!";echo

echo "Connecting to Terminal, Please wait"

status=$(ssh -o LogLevel=quiet -o StrictHostKeyChecking=no -i /tmp/mssh/.ssh/id_rsa ec2-user@`echo $IP` "ls -l file.pem" 2>/dev/null | awk '{print $9}')

while [ "${status}" != "file.pem" ]; do status=$(ssh -o LogLevel=quiet -o StrictHostKeyChecking=no -i /tmp/mssh/.ssh/id_rsa ec2-user@`echo $IP` "ls -l file.pem" 2>/dev/null | awk '{print $9}'); sleep 1; done

ssh -o LogLevel=quiet -o StrictHostKeyChecking=no -i /tmp/mssh/.ssh/id_rsa ec2-user@`echo $IP` -t "ssh -o LogLevel=quiet -o StrictHostKeyChecking=no -i file.pem admin@`echo $FWIP`"

terraform destroy -auto-approve > /dev/null &

pid=$! # Process Id of the previous running command

spin[0]="-";spin[1]="\\";spin[2]="|";spin[3]="/";echo;echo -n "Terminating the Instance ......... ${spin[0]}"

while kill -0 $pid 2>/dev/null; do for i in "${spin[@]}"; do echo -ne "\b$i"; sleep 0.1; done; done

rm terraform.tfstate terraform.tfstate.backup

echo;echo "Terminated Fwaas Jumpbox !!";echo
