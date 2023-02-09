provider "aws" {
  region     = "ap-southeast-2"
  access_key = var.access_key
  secret_key = var.secret_key
}

variable "access_key" {
  type = string
}

variable "secret_key" {
  type = string
}

resource "aws_instance" "example" {
  ami           = "ami-043e0add5c8665836"
  instance_type = "t2.micro"
}
