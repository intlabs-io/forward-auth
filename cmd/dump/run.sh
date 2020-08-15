#!/bin/bash

cmd=$(basename $0)

usage() {
  echo -e usage: $cmd 'dev|tst|pvw|stg|prd'
  echo -e "  $1"
  exit 1
}

if [ $# != 1 ]; then
  usage "platform must be provided"
fi

export ENV="$1"
if [ "$ENV" != "dev" -a "$ENV" != "tst" -a "$ENV" != "pvw" -a "$ENV" != "stg" -a "$ENV" != "prd" ]; then
  usage
fi

if [ ! -f $ENV.in ]; then
  usage "$ENV.in does not exist"
fi

source $ENV.in

./dump  -level DEBUG

