#!/bin/bash

cmd=$(basename $0)

usage() {
  echo -e usage: "$cmd 'dev|tst|pvw|stg|prd' [-level LEVEL] FILE"
  echo -e "  $1"
  exit 1
}

if [ $# != 2 ]; then
  usage 
fi

export ENV="$1"
if [ "$ENV" != "dev" -a "$ENV" != "tst" -a "$ENV" != "pvw" -a "$ENV" != "stg" -a "$ENV" != "prd" ]; then
  usage "invalid platform $ENV"
fi

if [ ! -f $ENV.in ]; then
  usage "$ENV.in does not exist"
fi

source $ENV.in

file=$2

./load  -level DEBUG -file $file

