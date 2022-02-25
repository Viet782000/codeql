# -*- coding: utf-8 -*-
#
# CodeQL analysis support for LGTM Enterprise docs build configuration file.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

# For details of all possible config values, 
# see https://www.sphinx-doc.org/en/master/usage/configuration.html

##############################################################################
#
# Modified 22032021. 

# The configuration values below are specific to the supported languages and frameworks project
# To amend html_theme_options, update version/release number, or add more sphinx extensions,
# refer to code/documentation/ql-documentation/global-sphinx-files/global-conf.py

##############################################################################

# -- Project-specific configuration -----------------------------------

# Set QL as the default language for highlighting code. Set to none to disable 
# syntax highlighting. If omitted or left blank, it defaults to Python 3. 
highlight_language = 'none'

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# The master toctree document.
master_doc = 'index'

# Project-specific information.
project = u'Supported languages and frameworks for LGTM Enterprise'

# The version info for this project, if different from version and release in main conf.py file.
# The short X.Y version.

# LGTM Enterprise release
release = u'1.29'

# CodeQL CLI version used by LGTM Enterprise release
version = u'2.6.3'

# -- Project-specifc options for HTML output ----------------------------------------------

# The name for this set of Sphinx documents.  If None, it defaults to
# "<project> v<release> documentation".
html_title = 'Supported languages and frameworks'

# Output file base name for HTML help builder.
htmlhelp_basename = 'Supported languages and frameworks'

# Add any paths that contain templates here, relative to this directory.
templates_path = ['../_templates']

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['../_static']

html_theme_options = {'font_size': '16px',
                      'body_text': '#333', 
                      'link': '#2F1695',
                      'link_hover': '#2F1695',
                      'font_family': 'Inter,-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif,Segoe UI Symbol;',
                      'show_powered_by': False,
                      'nosidebar':True,
                      }

html_favicon = '../images/site/favicon.ico'

# -- Currently unused, but potentially useful, configs--------------------------------------

# Add any paths that contain custom themes here, relative to this directory.
#html_theme_path = []

# A shorter title for the navigation bar.  Default is the same as html_title.
#html_short_title = None

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
#html_logo = None

# Custom sidebar templates, maps document names to template names.
#html_sidebars = {}

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
#html_extra_path = []

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['read-me-project.rst', 'reusables/*']
