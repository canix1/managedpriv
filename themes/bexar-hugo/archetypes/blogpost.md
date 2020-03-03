
---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
# meta description
description: "this is meta description for blog page."
# page title background image
bg_image_webp: "images/backgrounds/page-title.webp"
bg_image: "images/backgrounds/page-title.jpg"
# post thumbnail
image: "images/blog/post-1.webp"
image_webp: "images/blog/post-1.jpg"
# post author
author: "Robin Granberg"
# taxonomies
categories: [""]
tags: [""]
# type
type: "post"


---



{{ range first 10 ( where .Site.RegularPages "Type" "cool" ) }}
* {{ .Title }}
{{ end }}