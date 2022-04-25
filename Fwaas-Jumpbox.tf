variable "region" {
  description = "Enter Region"

}

variable "env" {
  description = "Which enviornment to use"
}

provider "aws" {
  region     = "${var.region}"
  profile    = "MSSH"

}

data "aws_vpc" "icvpc" {
	filter {
		name  = "tag:Name"
		values = ["vpc_sre_jumpbox"]

               }
}



data "aws_subnet_ids" "icsubnet" {
 
  vpc_id = data.aws_vpc.icvpc.id
  
	filter {
                name  = "tag:Subnet_type"
                values = ["vpc_sre_jumpbox_public"]

               }
}


data "aws_ami" "IC" {
 most_recent = true
 owners =  ["amazon"]

 filter {
   name   = "owner-alias"
   values = ["amazon"]
 }


 filter {
   name   = "name"
   values = ["amzn2-ami-hvm*"]
 }
}

data "http" "mypubip" {

  url = "http://ipv4.icanhazip.com"
}


resource "aws_security_group" "allow_ssh" {
  description = "Allow SSH  inbound traffic"
  vpc_id = data.aws_vpc.icvpc.id


ingress {
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = ["${chomp(data.http.mypubip.body)}/32"]
  }

egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

tags = {
    Name = "allow_ssh"
  }

}


resource "aws_iam_role" "icrole" {
 description = "SSM policy will be attached to this Role "
 path = "/"
 assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

 tags = {
    Fwaas = "Jumphost"
  }

}

resource "aws_iam_role_policy" "icpolicy" {
  name = "jumphost_policy"
  role = aws_iam_role.icrole.id

   #Terraform's "jsonencode" function converts a
   #Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_instance_profile" "icprofile" {
  role = "${aws_iam_role.icrole.name}"
}

resource "aws_instance" "IC-Test3" {
  ami           = "${data.aws_ami.IC.id}"
  instance_type = "t2.micro"
  iam_instance_profile = "${aws_iam_instance_profile.icprofile.name}"
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]
  associate_public_ip_address = true
  subnet_id              = tolist(data.aws_subnet_ids.icsubnet.ids)[0]
  user_data = <<EOF
#!/bin/bash

sudo yum install jq -y

pip3 install ec2instanceconnectcli

eval $(aws sts assume-role --role-arn arn:aws:iam::551899637894:role/Terraform-secretmanager --role-session-name sm | jq -r '.Credentials | "export AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nexport AWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nexport AWS_SESSION_TOKEN=\(.SessionToken)\n"')

aws secretsmanager get-secret-value --secret-id "fwaas/sre/${var.env}/fwssh-${var.region}" --region us-west-2 | jq  '.SecretString' | awk -F'\"' '{print $5}' | sed 's/.$//' | sed 's/\\n/\n/g' > /home/ec2-user/file.pem

if [ -f "file.pem" ]; then echo "OK"; else echo "aws secretsmanager get-secret-value --secret-id "fwaas/sre/${var.env}/fwssh-${var.region}" --region us-west-2 | jq  '.SecretString' | awk -F'\"' '{print $5}' | sed 's/.$//' | sed 's/\\n/\n/g' > /home/ec2-user/file.pem"; fi

if [ -s "file.pem" ]; then echo "OK"; else echo "aws secretsmanager get-secret-value --secret-id "fwaas/sre/${var.env}/fwssh-${var.region}" --region us-west-2 | jq  '.SecretString' | awk -F'\"' '{print $5}' | sed 's/.$//' | sed 's/\\n/\n/g' > /home/ec2-user/file.pem"; fi


sudo chown ec2-user:ec2-user /home/ec2-user/file.pem 

chmod 400 /home/ec2-user/file.pem

EOF


  tags = {
    Name = "Jumphost Fwaas"
   }
}
