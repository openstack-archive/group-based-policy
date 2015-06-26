


<!DOCTYPE html>
<html lang="en" class="">
  <head prefix="og: http://ogp.me/ns# fb: http://ogp.me/ns/fb# object: http://ogp.me/ns/object# article: http://ogp.me/ns/article# profile: http://ogp.me/ns/profile#">
    <meta charset='utf-8'>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta http-equiv="Content-Language" content="en">
    
    
    <title>devstack/gbp_fip.sh at gbp-kilo-gate · group-policy/devstack · GitHub</title>
    <link rel="search" type="application/opensearchdescription+xml" href="/opensearch.xml" title="GitHub">
    <link rel="fluid-icon" href="https://github.com/fluidicon.png" title="GitHub">
    <link rel="apple-touch-icon" sizes="57x57" href="/apple-touch-icon-114.png">
    <link rel="apple-touch-icon" sizes="114x114" href="/apple-touch-icon-114.png">
    <link rel="apple-touch-icon" sizes="72x72" href="/apple-touch-icon-144.png">
    <link rel="apple-touch-icon" sizes="144x144" href="/apple-touch-icon-144.png">
    <meta property="fb:app_id" content="1401488693436528">

      <meta content="@github" name="twitter:site" /><meta content="summary" name="twitter:card" /><meta content="group-policy/devstack" name="twitter:title" /><meta content="devstack - oneiric powered development environment for openstack" name="twitter:description" /><meta content="https://avatars2.githubusercontent.com/u/8683599?v=3&amp;s=400" name="twitter:image:src" />
      <meta content="GitHub" property="og:site_name" /><meta content="object" property="og:type" /><meta content="https://avatars2.githubusercontent.com/u/8683599?v=3&amp;s=400" property="og:image" /><meta content="group-policy/devstack" property="og:title" /><meta content="https://github.com/group-policy/devstack" property="og:url" /><meta content="devstack - oneiric powered development environment for openstack" property="og:description" />
      <meta name="browser-stats-url" content="https://api.github.com/_private/browser/stats">
    <meta name="browser-errors-url" content="https://api.github.com/_private/browser/errors">
    <link rel="assets" href="https://assets-cdn.github.com/">
    
    <meta name="pjax-timeout" content="1000">
    

    <meta name="msapplication-TileImage" content="/windows-tile.png">
    <meta name="msapplication-TileColor" content="#ffffff">
    <meta name="selected-link" value="repo_source" data-pjax-transient>

        <meta name="google-analytics" content="UA-3769691-2">

    <meta content="collector.githubapp.com" name="octolytics-host" /><meta content="collector-cdn.github.com" name="octolytics-script-host" /><meta content="github" name="octolytics-app-id" /><meta content="1882E349:4621:3F84AA0:558F7FB4" name="octolytics-dimension-request_id" />
    
    <meta content="Rails, view, blob#show" name="analytics-event" />
    <meta class="js-ga-set" name="dimension1" content="Logged Out">
    <meta name="is-dotcom" content="true">
      <meta name="hostname" content="github.com">
    <meta name="user-login" content="">

      <link rel="icon" sizes="any" mask href="https://assets-cdn.github.com/pinned-octocat.svg">
      <meta name="theme-color" content="#4078c0">
      <link rel="icon" type="image/x-icon" href="https://assets-cdn.github.com/favicon.ico">


    <meta content="authenticity_token" name="csrf-param" />
<meta content="+ZxDvZBJ+DWroT+VSwpU7Lfnad6OxOSjg77/teGSX9hV6QWmILWYRbYFBTiuTbnvlYJi7+F9X9t9a1BPOpVoug==" name="csrf-token" />

    <link crossorigin="anonymous" href="https://assets-cdn.github.com/assets/github/index-92f695d016fa2589aca5a191af0ebb39db49a57eaf23a045c8b2d79107c380dc.css" media="all" rel="stylesheet" />
    <link crossorigin="anonymous" href="https://assets-cdn.github.com/assets/github2/index-53b81bbd58011083c0ec0ad891de925f2dc177a927a56ebeed25af072f386e72.css" media="all" rel="stylesheet" />
    
    


    <meta http-equiv="x-pjax-version" content="0583d2af982402f4347c7b2ddba918d9">

      
  <meta name="description" content="devstack - oneiric powered development environment for openstack">
  <meta name="go-import" content="github.com/group-policy/devstack git https://github.com/group-policy/devstack.git">

  <meta content="8683599" name="octolytics-dimension-user_id" /><meta content="group-policy" name="octolytics-dimension-user_login" /><meta content="23825066" name="octolytics-dimension-repository_id" /><meta content="group-policy/devstack" name="octolytics-dimension-repository_nwo" /><meta content="true" name="octolytics-dimension-repository_public" /><meta content="true" name="octolytics-dimension-repository_is_fork" /><meta content="2790220" name="octolytics-dimension-repository_parent_id" /><meta content="openstack-dev/devstack" name="octolytics-dimension-repository_parent_nwo" /><meta content="2790220" name="octolytics-dimension-repository_network_root_id" /><meta content="openstack-dev/devstack" name="octolytics-dimension-repository_network_root_nwo" />
  <link href="https://github.com/group-policy/devstack/commits/gbp-kilo-gate.atom" rel="alternate" title="Recent Commits to devstack:gbp-kilo-gate" type="application/atom+xml">

  </head>


  <body class="logged_out  env-production  vis-public fork page-blob">
    <a href="#start-of-content" tabindex="1" class="accessibility-aid js-skip-to-content">Skip to content</a>
    <div class="wrapper">
      
      
      


        
        <div class="header header-logged-out" role="banner">
  <div class="container clearfix">

    <a class="header-logo-wordmark" href="https://github.com/" data-ga-click="(Logged out) Header, go to homepage, icon:logo-wordmark">
      <span class="mega-octicon octicon-logo-github"></span>
    </a>

    <div class="header-actions" role="navigation">
        <a class="btn btn-primary" href="/join" data-ga-click="(Logged out) Header, clicked Sign up, text:sign-up">Sign up</a>
      <a class="btn" href="/login?return_to=%2Fgroup-policy%2Fdevstack%2Fblob%2Fgbp-kilo-gate%2Fexercises%2Fgbp_fip.sh" data-ga-click="(Logged out) Header, clicked Sign in, text:sign-in">Sign in</a>
    </div>

    <div class="site-search repo-scope js-site-search" role="search">
      <form accept-charset="UTF-8" action="/group-policy/devstack/search" class="js-site-search-form" data-global-search-url="/search" data-repo-search-url="/group-policy/devstack/search" method="get"><div style="margin:0;padding:0;display:inline"><input name="utf8" type="hidden" value="&#x2713;" /></div>
  <label class="js-chromeless-input-container form-control">
    <div class="scope-badge">This repository</div>
    <input type="text"
      class="js-site-search-focus js-site-search-field is-clearable chromeless-input"
      data-hotkey="s"
      name="q"
      placeholder="Search"
      data-global-scope-placeholder="Search GitHub"
      data-repo-scope-placeholder="Search"
      tabindex="1"
      autocapitalize="off">
  </label>
</form>
    </div>

      <ul class="header-nav left" role="navigation">
          <li class="header-nav-item">
            <a class="header-nav-link" href="/explore" data-ga-click="(Logged out) Header, go to explore, text:explore">Explore</a>
          </li>
          <li class="header-nav-item">
            <a class="header-nav-link" href="/features" data-ga-click="(Logged out) Header, go to features, text:features">Features</a>
          </li>
          <li class="header-nav-item">
            <a class="header-nav-link" href="https://enterprise.github.com/" data-ga-click="(Logged out) Header, go to enterprise, text:enterprise">Enterprise</a>
          </li>
          <li class="header-nav-item">
            <a class="header-nav-link" href="/blog" data-ga-click="(Logged out) Header, go to blog, text:blog">Blog</a>
          </li>
      </ul>

  </div>
</div>



      <div id="start-of-content" class="accessibility-aid"></div>
          <div class="site" itemscope itemtype="http://schema.org/WebPage">
    <div id="js-flash-container">
      
    </div>
    <div class="pagehead repohead instapaper_ignore readability-menu">
      <div class="container">

        
<ul class="pagehead-actions">

  <li>
      <a href="/login?return_to=%2Fgroup-policy%2Fdevstack"
    class="btn btn-sm btn-with-count tooltipped tooltipped-n"
    aria-label="You must be signed in to watch a repository" rel="nofollow">
    <span class="octicon octicon-eye"></span>
    Watch
  </a>
  <a class="social-count" href="/group-policy/devstack/watchers">
    15
  </a>

  </li>

  <li>
      <a href="/login?return_to=%2Fgroup-policy%2Fdevstack"
    class="btn btn-sm btn-with-count tooltipped tooltipped-n"
    aria-label="You must be signed in to star a repository" rel="nofollow">
    <span class="octicon octicon-star"></span>
    Star
  </a>

    <a class="social-count js-social-count" href="/group-policy/devstack/stargazers">
      3
    </a>

  </li>

    <li>
      <a href="/login?return_to=%2Fgroup-policy%2Fdevstack"
        class="btn btn-sm btn-with-count tooltipped tooltipped-n"
        aria-label="You must be signed in to fork a repository" rel="nofollow">
        <span class="octicon octicon-repo-forked"></span>
        Fork
      </a>
      <a href="/group-policy/devstack/network" class="social-count">
        805
      </a>
    </li>
</ul>

        <h1 itemscope itemtype="http://data-vocabulary.org/Breadcrumb" class="entry-title public">
          <span class="mega-octicon octicon-repo-forked"></span>
          <span class="author"><a href="/group-policy" class="url fn" itemprop="url" rel="author"><span itemprop="title">group-policy</span></a></span><!--
       --><span class="path-divider">/</span><!--
       --><strong><a href="/group-policy/devstack" data-pjax="#js-repo-pjax-container">devstack</a></strong>

          <span class="page-context-loader">
            <img alt="" height="16" src="https://assets-cdn.github.com/images/spinners/octocat-spinner-32.gif" width="16" />
          </span>

            <span class="fork-flag">
              <span class="text">forked from <a href="/openstack-dev/devstack">openstack-dev/devstack</a></span>
            </span>
        </h1>
      </div><!-- /.container -->
    </div><!-- /.repohead -->

    <div class="container">
      <div class="repository-with-sidebar repo-container new-discussion-timeline  ">
        <div class="repository-sidebar clearfix">
            
<nav class="sunken-menu repo-nav js-repo-nav js-sidenav-container-pjax js-octicon-loaders"
     role="navigation"
     data-pjax="#js-repo-pjax-container"
     data-issue-count-url="/group-policy/devstack/issues/counts">
  <ul class="sunken-menu-group">
    <li class="tooltipped tooltipped-w" aria-label="Code">
      <a href="/group-policy/devstack/tree/gbp-kilo-gate" aria-label="Code" class="selected js-selected-navigation-item sunken-menu-item" data-hotkey="g c" data-selected-links="repo_source repo_downloads repo_commits repo_releases repo_tags repo_branches /group-policy/devstack/tree/gbp-kilo-gate">
        <span class="octicon octicon-code"></span> <span class="full-word">Code</span>
        <img alt="" class="mini-loader" height="16" src="https://assets-cdn.github.com/images/spinners/octocat-spinner-32.gif" width="16" />
</a>    </li>

      <li class="tooltipped tooltipped-w" aria-label="Issues">
        <a href="/group-policy/devstack/issues" aria-label="Issues" class="js-selected-navigation-item sunken-menu-item" data-hotkey="g i" data-selected-links="repo_issues repo_labels repo_milestones /group-policy/devstack/issues">
          <span class="octicon octicon-issue-opened"></span> <span class="full-word">Issues</span>
          <span class="js-issue-replace-counter"></span>
          <img alt="" class="mini-loader" height="16" src="https://assets-cdn.github.com/images/spinners/octocat-spinner-32.gif" width="16" />
</a>      </li>

    <li class="tooltipped tooltipped-w" aria-label="Pull requests">
      <a href="/group-policy/devstack/pulls" aria-label="Pull requests" class="js-selected-navigation-item sunken-menu-item" data-hotkey="g p" data-selected-links="repo_pulls /group-policy/devstack/pulls">
          <span class="octicon octicon-git-pull-request"></span> <span class="full-word">Pull requests</span>
          <span class="js-pull-replace-counter"></span>
          <img alt="" class="mini-loader" height="16" src="https://assets-cdn.github.com/images/spinners/octocat-spinner-32.gif" width="16" />
</a>    </li>

  </ul>
  <div class="sunken-menu-separator"></div>
  <ul class="sunken-menu-group">

    <li class="tooltipped tooltipped-w" aria-label="Pulse">
      <a href="/group-policy/devstack/pulse" aria-label="Pulse" class="js-selected-navigation-item sunken-menu-item" data-selected-links="pulse /group-policy/devstack/pulse">
        <span class="octicon octicon-pulse"></span> <span class="full-word">Pulse</span>
        <img alt="" class="mini-loader" height="16" src="https://assets-cdn.github.com/images/spinners/octocat-spinner-32.gif" width="16" />
</a>    </li>

    <li class="tooltipped tooltipped-w" aria-label="Graphs">
      <a href="/group-policy/devstack/graphs" aria-label="Graphs" class="js-selected-navigation-item sunken-menu-item" data-selected-links="repo_graphs repo_contributors /group-policy/devstack/graphs">
        <span class="octicon octicon-graph"></span> <span class="full-word">Graphs</span>
        <img alt="" class="mini-loader" height="16" src="https://assets-cdn.github.com/images/spinners/octocat-spinner-32.gif" width="16" />
</a>    </li>
  </ul>


</nav>

              <div class="only-with-full-nav">
                  
<div class="js-clone-url clone-url open"
  data-protocol-type="http">
  <h3><span class="text-emphasized">HTTPS</span> clone URL</h3>
  <div class="input-group js-zeroclipboard-container">
    <input type="text" class="input-mini input-monospace js-url-field js-zeroclipboard-target"
           value="https://github.com/group-policy/devstack.git" readonly="readonly">
    <span class="input-group-button">
      <button aria-label="Copy to clipboard" class="js-zeroclipboard btn btn-sm zeroclipboard-button tooltipped tooltipped-s" data-copied-hint="Copied!" type="button"><span class="octicon octicon-clippy"></span></button>
    </span>
  </div>
</div>

  
<div class="js-clone-url clone-url "
  data-protocol-type="subversion">
  <h3><span class="text-emphasized">Subversion</span> checkout URL</h3>
  <div class="input-group js-zeroclipboard-container">
    <input type="text" class="input-mini input-monospace js-url-field js-zeroclipboard-target"
           value="https://github.com/group-policy/devstack" readonly="readonly">
    <span class="input-group-button">
      <button aria-label="Copy to clipboard" class="js-zeroclipboard btn btn-sm zeroclipboard-button tooltipped tooltipped-s" data-copied-hint="Copied!" type="button"><span class="octicon octicon-clippy"></span></button>
    </span>
  </div>
</div>



<div class="clone-options">You can clone with
  <form accept-charset="UTF-8" action="/users/set_protocol?protocol_selector=http&amp;protocol_type=clone" class="inline-form js-clone-selector-form " data-remote="true" method="post"><div style="margin:0;padding:0;display:inline"><input name="utf8" type="hidden" value="&#x2713;" /><input name="authenticity_token" type="hidden" value="k6SsfIUDk96cStj5pQD8X+PeGQIO/khNmvUrAVQXo0kWKRdB3Ibx0eBD6FsZMbQ2IUT7tsyZpoaRCLHKFF/R8w==" /></div><button class="btn-link js-clone-selector" data-protocol="http" type="submit">HTTPS</button></form> or <form accept-charset="UTF-8" action="/users/set_protocol?protocol_selector=subversion&amp;protocol_type=clone" class="inline-form js-clone-selector-form " data-remote="true" method="post"><div style="margin:0;padding:0;display:inline"><input name="utf8" type="hidden" value="&#x2713;" /><input name="authenticity_token" type="hidden" value="KWaV7hQMukWQO3ZgwzifwsZUme7YA1GvnML4Pt+qm7r4OwTN6Go+zodMouk6I5e0SSSNFC33nEEBZCYIOlIW5w==" /></div><button class="btn-link js-clone-selector" data-protocol="subversion" type="submit">Subversion</button></form>.
  <a href="https://help.github.com/articles/which-remote-url-should-i-use" class="help tooltipped tooltipped-n" aria-label="Get help on which URL is right for you.">
    <span class="octicon octicon-question"></span>
  </a>
</div>




                <a href="/group-policy/devstack/archive/gbp-kilo-gate.zip"
                   class="btn btn-sm sidebar-button"
                   aria-label="Download the contents of group-policy/devstack as a zip file"
                   title="Download the contents of group-policy/devstack as a zip file"
                   rel="nofollow">
                  <span class="octicon octicon-cloud-download"></span>
                  Download ZIP
                </a>
              </div>
        </div><!-- /.repository-sidebar -->

        <div id="js-repo-pjax-container" class="repository-content context-loader-container" data-pjax-container>

          

<a href="/group-policy/devstack/blob/ae753f75d2e8327c04116287aeed4f47a671d529/exercises/gbp_fip.sh" class="hidden js-permalink-shortcut" data-hotkey="y">Permalink</a>

<!-- blob contrib key: blob_contributors:v21:cd32edda509f097743a95923b1f3094f -->

<div class="file-navigation js-zeroclipboard-container">
  
<div class="select-menu js-menu-container js-select-menu left">
  <span class="btn btn-sm select-menu-button js-menu-target css-truncate" data-hotkey="w"
    data-ref="gbp-kilo-gate"
    title="gbp-kilo-gate"
    role="button" aria-label="Switch branches or tags" tabindex="0" aria-haspopup="true">
    <span class="octicon octicon-git-branch"></span>
    <i>branch:</i>
    <span class="js-select-button css-truncate-target">gbp-kilo-gate</span>
  </span>

  <div class="select-menu-modal-holder js-menu-content js-navigation-container" data-pjax aria-hidden="true">

    <div class="select-menu-modal">
      <div class="select-menu-header">
        <span class="select-menu-title">Switch branches/tags</span>
        <span class="octicon octicon-x js-menu-close" role="button" aria-label="Close"></span>
      </div>

      <div class="select-menu-filters">
        <div class="select-menu-text-filter">
          <input type="text" aria-label="Filter branches/tags" id="context-commitish-filter-field" class="js-filterable-field js-navigation-enable" placeholder="Filter branches/tags">
        </div>
        <div class="select-menu-tabs">
          <ul>
            <li class="select-menu-tab">
              <a href="#" data-tab-filter="branches" data-filter-placeholder="Filter branches/tags" class="js-select-menu-tab">Branches</a>
            </li>
            <li class="select-menu-tab">
              <a href="#" data-tab-filter="tags" data-filter-placeholder="Find a tag…" class="js-select-menu-tab">Tags</a>
            </li>
          </ul>
        </div>
      </div>

      <div class="select-menu-list select-menu-tab-bucket js-select-menu-tab-bucket" data-tab-filter="branches">

        <div data-filterable-for="context-commitish-filter-field" data-filterable-type="substring">


            <a class="select-menu-item js-navigation-item js-navigation-open selected"
               href="/group-policy/devstack/blob/gbp-kilo-gate/exercises/gbp_fip.sh"
               data-name="gbp-kilo-gate"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="gbp-kilo-gate">
                gbp-kilo-gate
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/kilo-gbp/exercises/gbp_fip.sh"
               data-name="kilo-gbp"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="kilo-gbp">
                kilo-gbp
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/kilo-gbp-lab/exercises/gbp_fip.sh"
               data-name="kilo-gbp-lab"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="kilo-gbp-lab">
                kilo-gbp-lab
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/kilo-gbp-openstack-master-gate/exercises/gbp_fip.sh"
               data-name="kilo-gbp-openstack-master-gate"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="kilo-gbp-openstack-master-gate">
                kilo-gbp-openstack-master-gate
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/master/exercises/gbp_fip.sh"
               data-name="master"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="master">
                master
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno/exercises/gbp_fip.sh"
               data-name="stable/juno"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno">
                stable/juno
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno-gbp/exercises/gbp_fip.sh"
               data-name="stable/juno-gbp"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno-gbp">
                stable/juno-gbp
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno-gbp-apic/exercises/gbp_fip.sh"
               data-name="stable/juno-gbp-apic"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno-gbp-apic">
                stable/juno-gbp-apic
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno-gbp-gate/exercises/gbp_fip.sh"
               data-name="stable/juno-gbp-gate"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno-gbp-gate">
                stable/juno-gbp-gate
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno-gbp-nuage/exercises/gbp_fip.sh"
               data-name="stable/juno-gbp-nuage"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno-gbp-nuage">
                stable/juno-gbp-nuage
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno-gbp-oc/exercises/gbp_fip.sh"
               data-name="stable/juno-gbp-oc"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno-gbp-oc">
                stable/juno-gbp-oc
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/juno-gbp-odl/exercises/gbp_fip.sh"
               data-name="stable/juno-gbp-odl"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/juno-gbp-odl">
                stable/juno-gbp-odl
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/stable/kilo/exercises/gbp_fip.sh"
               data-name="stable/kilo"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="stable/kilo">
                stable/kilo
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/test-fip-exercices-juno-gate/exercises/gbp_fip.sh"
               data-name="test-fip-exercices-juno-gate"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="test-fip-exercices-juno-gate">
                test-fip-exercices-juno-gate
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/test-gbp-fip-exercise-on-master-gate/exercises/gbp_fip.sh"
               data-name="test-gbp-fip-exercise-on-master-gate"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="test-gbp-fip-exercise-on-master-gate">
                test-gbp-fip-exercise-on-master-gate
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/test-gbp-service-exercises-on-kilo/exercises/gbp_fip.sh"
               data-name="test-gbp-service-exercises-on-kilo"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="test-gbp-service-exercises-on-kilo">
                test-gbp-service-exercises-on-kilo
              </span>
            </a>
            <a class="select-menu-item js-navigation-item js-navigation-open "
               href="/group-policy/devstack/blob/test-gbp-service-exercises-on-kilo-gate/exercises/gbp_fip.sh"
               data-name="test-gbp-service-exercises-on-kilo-gate"
               data-skip-pjax="true"
               rel="nofollow">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <span class="select-menu-item-text css-truncate-target" title="test-gbp-service-exercises-on-kilo-gate">
                test-gbp-service-exercises-on-kilo-gate
              </span>
            </a>
        </div>

          <div class="select-menu-no-results">Nothing to show</div>
      </div>

      <div class="select-menu-list select-menu-tab-bucket js-select-menu-tab-bucket" data-tab-filter="tags">
        <div data-filterable-for="context-commitish-filter-field" data-filterable-type="substring">


            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/group-policy/devstack/tree/grizzly-eol/exercises/gbp_fip.sh"
                 data-name="grizzly-eol"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text css-truncate-target"
                 title="grizzly-eol">grizzly-eol</a>
            </div>
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/group-policy/devstack/tree/folsom-eol/exercises/gbp_fip.sh"
                 data-name="folsom-eol"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text css-truncate-target"
                 title="folsom-eol">folsom-eol</a>
            </div>
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/group-policy/devstack/tree/essex-eol/exercises/gbp_fip.sh"
                 data-name="essex-eol"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text css-truncate-target"
                 title="essex-eol">essex-eol</a>
            </div>
            <div class="select-menu-item js-navigation-item ">
              <span class="select-menu-item-icon octicon octicon-check"></span>
              <a href="/group-policy/devstack/tree/diablo-eol/exercises/gbp_fip.sh"
                 data-name="diablo-eol"
                 data-skip-pjax="true"
                 rel="nofollow"
                 class="js-navigation-open select-menu-item-text css-truncate-target"
                 title="diablo-eol">diablo-eol</a>
            </div>
        </div>

        <div class="select-menu-no-results">Nothing to show</div>
      </div>

    </div>
  </div>
</div>

  <div class="btn-group right">
    <a href="/group-policy/devstack/find/gbp-kilo-gate"
          class="js-show-file-finder btn btn-sm empty-icon tooltipped tooltipped-s"
          data-pjax
          data-hotkey="t"
          aria-label="Quickly jump between files">
      <span class="octicon octicon-list-unordered"></span>
    </a>
    <button aria-label="Copy file path to clipboard" class="js-zeroclipboard btn btn-sm zeroclipboard-button tooltipped tooltipped-s" data-copied-hint="Copied!" type="button"><span class="octicon octicon-clippy"></span></button>
  </div>

  <div class="breadcrumb js-zeroclipboard-target">
    <span class="repo-root js-repo-root"><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/group-policy/devstack/tree/gbp-kilo-gate" class="" data-branch="gbp-kilo-gate" data-pjax="true" itemscope="url"><span itemprop="title">devstack</span></a></span></span><span class="separator">/</span><span itemscope="" itemtype="http://data-vocabulary.org/Breadcrumb"><a href="/group-policy/devstack/tree/gbp-kilo-gate/exercises" class="" data-branch="gbp-kilo-gate" data-pjax="true" itemscope="url"><span itemprop="title">exercises</span></a></span><span class="separator">/</span><strong class="final-path">gbp_fip.sh</strong>
  </div>
</div>


  <div class="commit file-history-tease">
    <div class="file-history-tease-header">
        <img alt="@mageshgv" class="avatar" height="24" src="https://avatars0.githubusercontent.com/u/8311990?v=3&amp;s=48" width="24" />
        <span class="author"><a href="/mageshgv" rel="contributor">mageshgv</a></span>
        <time datetime="2015-06-01T06:34:22Z" is="relative-time">Jun 1, 2015</time>
        <div class="commit-title">
            <a href="/group-policy/devstack/commit/69d2c1ec8b698c54e28e895b2629470d42389b31" class="message" data-pjax="true" title="Add external net create to gbp_fip exercise if it is not created.">Add external net create to gbp_fip exercise if it is not created.</a>
        </div>
    </div>

    <div class="participation">
      <p class="quickstat">
        <a href="#blob_contributors_box" rel="facebox">
          <strong>1</strong>
           contributor
        </a>
      </p>
      
    </div>
    <div id="blob_contributors_box" style="display:none">
      <h2 class="facebox-header">Users who have contributed to this file</h2>
      <ul class="facebox-user-list">
          <li class="facebox-user-list-item">
            <img alt="@mageshgv" height="24" src="https://avatars0.githubusercontent.com/u/8311990?v=3&amp;s=48" width="24" />
            <a href="/mageshgv">mageshgv</a>
          </li>
      </ul>
    </div>
  </div>

<div class="file">
  <div class="file-header">
    <div class="file-actions">

      <div class="btn-group">
        <a href="/group-policy/devstack/raw/gbp-kilo-gate/exercises/gbp_fip.sh" class="btn btn-sm " id="raw-url">Raw</a>
          <a href="/group-policy/devstack/blame/gbp-kilo-gate/exercises/gbp_fip.sh" class="btn btn-sm js-update-url-with-hash">Blame</a>
        <a href="/group-policy/devstack/commits/gbp-kilo-gate/exercises/gbp_fip.sh" class="btn btn-sm " rel="nofollow">History</a>
      </div>


          <button type="button" class="octicon-btn disabled tooltipped tooltipped-n" aria-label="You must be signed in to make or propose changes">
            <span class="octicon octicon-pencil"></span>
          </button>

        <button type="button" class="octicon-btn octicon-btn-danger disabled tooltipped tooltipped-n" aria-label="You must be signed in to make or propose changes">
          <span class="octicon octicon-trashcan"></span>
        </button>
    </div>

    <div class="file-info">
        <span class="file-mode" title="File mode">executable file</span>
        <span class="file-info-divider"></span>
        123 lines (77 sloc)
        <span class="file-info-divider"></span>
      4.56 kB
    </div>
  </div>
  
  <div class="blob-wrapper data type-shell">
      <table class="highlight tab-size js-file-line-container" data-tab-size="8">
      <tr>
        <td id="L1" class="blob-num js-line-number" data-line-number="1"></td>
        <td id="LC1" class="blob-code blob-code-inner js-file-line"><span class="pl-c">#!/usr/bin/env bash</span></td>
      </tr>
      <tr>
        <td id="L2" class="blob-num js-line-number" data-line-number="2"></td>
        <td id="LC2" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L3" class="blob-num js-line-number" data-line-number="3"></td>
        <td id="LC3" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># **gbp_fip.sh**</span></td>
      </tr>
      <tr>
        <td id="L4" class="blob-num js-line-number" data-line-number="4"></td>
        <td id="LC4" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L5" class="blob-num js-line-number" data-line-number="5"></td>
        <td id="LC5" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Sanity check that gbp fip support works if enabled</span></td>
      </tr>
      <tr>
        <td id="L6" class="blob-num js-line-number" data-line-number="6"></td>
        <td id="LC6" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L7" class="blob-num js-line-number" data-line-number="7"></td>
        <td id="LC7" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>*********************************************************************<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L8" class="blob-num js-line-number" data-line-number="8"></td>
        <td id="LC8" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>Begin DevStack Exercise: <span class="pl-smi">$0</span><span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L9" class="blob-num js-line-number" data-line-number="9"></td>
        <td id="LC9" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>*********************************************************************<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L10" class="blob-num js-line-number" data-line-number="10"></td>
        <td id="LC10" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L11" class="blob-num js-line-number" data-line-number="11"></td>
        <td id="LC11" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># This script exits on an error so that errors don&#39;t compound and you see</span></td>
      </tr>
      <tr>
        <td id="L12" class="blob-num js-line-number" data-line-number="12"></td>
        <td id="LC12" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># only the first error that occurred.</span></td>
      </tr>
      <tr>
        <td id="L13" class="blob-num js-line-number" data-line-number="13"></td>
        <td id="LC13" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">set</span> -o errexit</td>
      </tr>
      <tr>
        <td id="L14" class="blob-num js-line-number" data-line-number="14"></td>
        <td id="LC14" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L15" class="blob-num js-line-number" data-line-number="15"></td>
        <td id="LC15" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Print the commands being run so that we can see the command that triggers</span></td>
      </tr>
      <tr>
        <td id="L16" class="blob-num js-line-number" data-line-number="16"></td>
        <td id="LC16" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># an error.  It is also useful for following allowing as the install occurs.</span></td>
      </tr>
      <tr>
        <td id="L17" class="blob-num js-line-number" data-line-number="17"></td>
        <td id="LC17" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">set</span> -o xtrace</td>
      </tr>
      <tr>
        <td id="L18" class="blob-num js-line-number" data-line-number="18"></td>
        <td id="LC18" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L19" class="blob-num js-line-number" data-line-number="19"></td>
        <td id="LC19" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L20" class="blob-num js-line-number" data-line-number="20"></td>
        <td id="LC20" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Settings</span></td>
      </tr>
      <tr>
        <td id="L21" class="blob-num js-line-number" data-line-number="21"></td>
        <td id="LC21" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># ========</span></td>
      </tr>
      <tr>
        <td id="L22" class="blob-num js-line-number" data-line-number="22"></td>
        <td id="LC22" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L23" class="blob-num js-line-number" data-line-number="23"></td>
        <td id="LC23" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Keep track of the current directory</span></td>
      </tr>
      <tr>
        <td id="L24" class="blob-num js-line-number" data-line-number="24"></td>
        <td id="LC24" class="blob-code blob-code-inner js-file-line">EXERCISE_DIR=<span class="pl-s"><span class="pl-pds">$(</span><span class="pl-c1">cd</span> <span class="pl-s"><span class="pl-pds">$(</span>dirname <span class="pl-s"><span class="pl-pds">&quot;</span><span class="pl-smi">$0</span><span class="pl-pds">&quot;</span></span><span class="pl-pds">)</span></span> <span class="pl-k">&amp;&amp;</span> <span class="pl-c1">pwd</span><span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L25" class="blob-num js-line-number" data-line-number="25"></td>
        <td id="LC25" class="blob-code blob-code-inner js-file-line">TOP_DIR=<span class="pl-s"><span class="pl-pds">$(</span><span class="pl-c1">cd</span> <span class="pl-smi">$EXERCISE_DIR</span>/..<span class="pl-k">;</span> <span class="pl-c1">pwd</span><span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L26" class="blob-num js-line-number" data-line-number="26"></td>
        <td id="LC26" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L27" class="blob-num js-line-number" data-line-number="27"></td>
        <td id="LC27" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Import common functions</span></td>
      </tr>
      <tr>
        <td id="L28" class="blob-num js-line-number" data-line-number="28"></td>
        <td id="LC28" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">source</span> <span class="pl-smi">$TOP_DIR</span>/functions</td>
      </tr>
      <tr>
        <td id="L29" class="blob-num js-line-number" data-line-number="29"></td>
        <td id="LC29" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L30" class="blob-num js-line-number" data-line-number="30"></td>
        <td id="LC30" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Import configuration</span></td>
      </tr>
      <tr>
        <td id="L31" class="blob-num js-line-number" data-line-number="31"></td>
        <td id="LC31" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">source</span> <span class="pl-smi">$TOP_DIR</span>/openrc</td>
      </tr>
      <tr>
        <td id="L32" class="blob-num js-line-number" data-line-number="32"></td>
        <td id="LC32" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L33" class="blob-num js-line-number" data-line-number="33"></td>
        <td id="LC33" class="blob-code blob-code-inner js-file-line"><span class="pl-c"># Import exercise configuration</span></td>
      </tr>
      <tr>
        <td id="L34" class="blob-num js-line-number" data-line-number="34"></td>
        <td id="LC34" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">source</span> <span class="pl-smi">$TOP_DIR</span>/exerciserc</td>
      </tr>
      <tr>
        <td id="L35" class="blob-num js-line-number" data-line-number="35"></td>
        <td id="LC35" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L36" class="blob-num js-line-number" data-line-number="36"></td>
        <td id="LC36" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">source</span> <span class="pl-smi">$TOP_DIR</span>/openrc admin admin</td>
      </tr>
      <tr>
        <td id="L37" class="blob-num js-line-number" data-line-number="37"></td>
        <td id="LC37" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L38" class="blob-num js-line-number" data-line-number="38"></td>
        <td id="LC38" class="blob-code blob-code-inner js-file-line"><span class="pl-k">function</span> <span class="pl-en">confirm_server_active</span> {</td>
      </tr>
      <tr>
        <td id="L39" class="blob-num js-line-number" data-line-number="39"></td>
        <td id="LC39" class="blob-code blob-code-inner js-file-line">    <span class="pl-k">local</span> VM_UUID=<span class="pl-smi">$1</span></td>
      </tr>
      <tr>
        <td id="L40" class="blob-num js-line-number" data-line-number="40"></td>
        <td id="LC40" class="blob-code blob-code-inner js-file-line">    <span class="pl-k">if</span> <span class="pl-k">!</span> timeout <span class="pl-smi">$ACTIVE_TIMEOUT</span> sh -c <span class="pl-s"><span class="pl-pds">&quot;</span>while ! nova show <span class="pl-smi">$VM_UUID</span> | grep status | grep -q ACTIVE; do sleep 1; done<span class="pl-pds">&quot;</span></span><span class="pl-k">;</span> <span class="pl-k">then</span></td>
      </tr>
      <tr>
        <td id="L41" class="blob-num js-line-number" data-line-number="41"></td>
        <td id="LC41" class="blob-code blob-code-inner js-file-line">        <span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>server &#39;<span class="pl-smi">$VM_UUID</span>&#39; did not become active!<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L42" class="blob-num js-line-number" data-line-number="42"></td>
        <td id="LC42" class="blob-code blob-code-inner js-file-line">        <span class="pl-c1">false</span></td>
      </tr>
      <tr>
        <td id="L43" class="blob-num js-line-number" data-line-number="43"></td>
        <td id="LC43" class="blob-code blob-code-inner js-file-line">    <span class="pl-k">fi</span></td>
      </tr>
      <tr>
        <td id="L44" class="blob-num js-line-number" data-line-number="44"></td>
        <td id="LC44" class="blob-code blob-code-inner js-file-line">}</td>
      </tr>
      <tr>
        <td id="L45" class="blob-num js-line-number" data-line-number="45"></td>
        <td id="LC45" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L46" class="blob-num js-line-number" data-line-number="46"></td>
        <td id="LC46" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L47" class="blob-num js-line-number" data-line-number="47"></td>
        <td id="LC47" class="blob-code blob-code-inner js-file-line">EXT_NET_ID=<span class="pl-s"><span class="pl-pds">$(</span>neutron net-list --router:external -c id <span class="pl-k">|</span> grep -v id <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $2}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L48" class="blob-num js-line-number" data-line-number="48"></td>
        <td id="LC48" class="blob-code blob-code-inner js-file-line">EXT_NET_TO_BE_CLEANED_UP=<span class="pl-c1">false</span></td>
      </tr>
      <tr>
        <td id="L49" class="blob-num js-line-number" data-line-number="49"></td>
        <td id="LC49" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L50" class="blob-num js-line-number" data-line-number="50"></td>
        <td id="LC50" class="blob-code blob-code-inner js-file-line"><span class="pl-k">if</span> [ -z <span class="pl-s"><span class="pl-pds">&quot;</span><span class="pl-smi">$EXT_NET_ID</span><span class="pl-pds">&quot;</span></span> ] <span class="pl-k">;</span> <span class="pl-k">then</span></td>
      </tr>
      <tr>
        <td id="L51" class="blob-num js-line-number" data-line-number="51"></td>
        <td id="LC51" class="blob-code blob-code-inner js-file-line">    EXT_NET_ID=<span class="pl-s"><span class="pl-pds">$(</span>neutron net-create <span class="pl-s"><span class="pl-pds">&quot;</span><span class="pl-smi">$PUBLIC_NETWORK_NAME</span><span class="pl-pds">&quot;</span></span> -- --router:external=True <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> get_field 2<span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L52" class="blob-num js-line-number" data-line-number="52"></td>
        <td id="LC52" class="blob-code blob-code-inner js-file-line">    EXT_SUBNET_ID=<span class="pl-s"><span class="pl-pds">$(</span>neutron subnet-create --ip_version 4 --gateway 172.16.73.1 --name public-subnet <span class="pl-smi">$EXT_NET_ID</span> 172.16.73.0/24 <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> get_field 2<span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L53" class="blob-num js-line-number" data-line-number="53"></td>
        <td id="LC53" class="blob-code blob-code-inner js-file-line">    EXT_NET_TO_BE_CLEANED_UP=<span class="pl-c1">true</span></td>
      </tr>
      <tr>
        <td id="L54" class="blob-num js-line-number" data-line-number="54"></td>
        <td id="LC54" class="blob-code blob-code-inner js-file-line"><span class="pl-k">else</span></td>
      </tr>
      <tr>
        <td id="L55" class="blob-num js-line-number" data-line-number="55"></td>
        <td id="LC55" class="blob-code blob-code-inner js-file-line">    EXT_NET_ID=<span class="pl-s"><span class="pl-pds">$(</span>neutron net-list --router:external -c id <span class="pl-k">|</span> grep -v id <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $2}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L56" class="blob-num js-line-number" data-line-number="56"></td>
        <td id="LC56" class="blob-code blob-code-inner js-file-line">    EXT_SUBNET_ID=<span class="pl-s"><span class="pl-pds">$(</span>neutron net-show <span class="pl-smi">$EXT_NET_ID</span> <span class="pl-k">|</span> grep subnets <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L57" class="blob-num js-line-number" data-line-number="57"></td>
        <td id="LC57" class="blob-code blob-code-inner js-file-line"><span class="pl-k">fi</span></td>
      </tr>
      <tr>
        <td id="L58" class="blob-num js-line-number" data-line-number="58"></td>
        <td id="LC58" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L59" class="blob-num js-line-number" data-line-number="59"></td>
        <td id="LC59" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> EXT_SUBNET_ID <span class="pl-s"><span class="pl-pds">&quot;</span>Failure creating external network<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L60" class="blob-num js-line-number" data-line-number="60"></td>
        <td id="LC60" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L61" class="blob-num js-line-number" data-line-number="61"></td>
        <td id="LC61" class="blob-code blob-code-inner js-file-line">EXT_SUBNET_CIDR=<span class="pl-s"><span class="pl-pds">$(</span>neutron subnet-show <span class="pl-smi">$EXT_SUBNET_ID</span> <span class="pl-k">|</span> grep cidr <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L62" class="blob-num js-line-number" data-line-number="62"></td>
        <td id="LC62" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L63" class="blob-num js-line-number" data-line-number="63"></td>
        <td id="LC63" class="blob-code blob-code-inner js-file-line">EXT_SUBNET_GW=<span class="pl-s"><span class="pl-pds">$(</span>neutron subnet-show <span class="pl-smi">$EXT_SUBNET_ID</span> <span class="pl-k">|</span> grep gateway_ip <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L64" class="blob-num js-line-number" data-line-number="64"></td>
        <td id="LC64" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L65" class="blob-num js-line-number" data-line-number="65"></td>
        <td id="LC65" class="blob-code blob-code-inner js-file-line">EXT_SEGMENT_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp external-segment-create --ip-version 4 --external-route destination=0.0.0.0/0,nexthop=<span class="pl-smi">$EXT_SUBNET_GW</span> --shared True --subnet_id=<span class="pl-smi">$EXT_SUBNET_ID</span>  --cidr <span class="pl-smi">$EXT_SUBNET_CIDR</span> default <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L66" class="blob-num js-line-number" data-line-number="66"></td>
        <td id="LC66" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L67" class="blob-num js-line-number" data-line-number="67"></td>
        <td id="LC67" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> EXT_SEGMENT_ID <span class="pl-s"><span class="pl-pds">&quot;</span>Failure creating external segment<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L68" class="blob-num js-line-number" data-line-number="68"></td>
        <td id="LC68" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L69" class="blob-num js-line-number" data-line-number="69"></td>
        <td id="LC69" class="blob-code blob-code-inner js-file-line">NAT_POOL_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp nat-pool-create --ip-version 4 --ip-pool <span class="pl-smi">$EXT_SUBNET_CIDR</span> --external-segment <span class="pl-smi">$EXT_SEGMENT_ID</span> ext_nat_pool <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L70" class="blob-num js-line-number" data-line-number="70"></td>
        <td id="LC70" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L71" class="blob-num js-line-number" data-line-number="71"></td>
        <td id="LC71" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> NAT_POOL_ID <span class="pl-s"><span class="pl-pds">&quot;</span>Failure creating nat pool<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L72" class="blob-num js-line-number" data-line-number="72"></td>
        <td id="LC72" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L73" class="blob-num js-line-number" data-line-number="73"></td>
        <td id="LC73" class="blob-code blob-code-inner js-file-line">NSP_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp network-service-policy-create --network-service-params <span class="pl-c1">type</span>=ip_pool,name=nat_fip,value=nat_pool nat_pool_nsp <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L74" class="blob-num js-line-number" data-line-number="74"></td>
        <td id="LC74" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L75" class="blob-num js-line-number" data-line-number="75"></td>
        <td id="LC75" class="blob-code blob-code-inner js-file-line">PTG_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp group-create --network-service-policy nat_pool_nsp provider_ptg <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L76" class="blob-num js-line-number" data-line-number="76"></td>
        <td id="LC76" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L77" class="blob-num js-line-number" data-line-number="77"></td>
        <td id="LC77" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> PTG_ID <span class="pl-s"><span class="pl-pds">&quot;</span>Failure creating ptg<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L78" class="blob-num js-line-number" data-line-number="78"></td>
        <td id="LC78" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L79" class="blob-num js-line-number" data-line-number="79"></td>
        <td id="LC79" class="blob-code blob-code-inner js-file-line">PT1_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp policy-target-create --policy-target-group provider_ptg provider_pt1 <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L80" class="blob-num js-line-number" data-line-number="80"></td>
        <td id="LC80" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L81" class="blob-num js-line-number" data-line-number="81"></td>
        <td id="LC81" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> PT1_ID <span class="pl-s"><span class="pl-pds">&quot;</span>Failure creating policy target<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L82" class="blob-num js-line-number" data-line-number="82"></td>
        <td id="LC82" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L83" class="blob-num js-line-number" data-line-number="83"></td>
        <td id="LC83" class="blob-code blob-code-inner js-file-line">PT2_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp policy-target-create --policy-target-group provider_ptg provider_pt2 <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L84" class="blob-num js-line-number" data-line-number="84"></td>
        <td id="LC84" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L85" class="blob-num js-line-number" data-line-number="85"></td>
        <td id="LC85" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> PT2_ID <span class="pl-s"><span class="pl-pds">&quot;</span>Failure creating policy target<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L86" class="blob-num js-line-number" data-line-number="86"></td>
        <td id="LC86" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L87" class="blob-num js-line-number" data-line-number="87"></td>
        <td id="LC87" class="blob-code blob-code-inner js-file-line">PT2_PORT_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp policy-target-show <span class="pl-smi">$PT2_ID</span> <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> port_id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L88" class="blob-num js-line-number" data-line-number="88"></td>
        <td id="LC88" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L89" class="blob-num js-line-number" data-line-number="89"></td>
        <td id="LC89" class="blob-code blob-code-inner js-file-line">PT2_PORT_IP=<span class="pl-s"><span class="pl-pds">$(</span>neutron port-show <span class="pl-smi">$PT2_PORT_ID</span> <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> fixed_ips <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $7}<span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk -F <span class="pl-s"><span class="pl-pds">&#39;</span>&quot;<span class="pl-pds">&#39;</span></span> <span class="pl-s"><span class="pl-pds">&#39;</span>{print $2}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L90" class="blob-num js-line-number" data-line-number="90"></td>
        <td id="LC90" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L91" class="blob-num js-line-number" data-line-number="91"></td>
        <td id="LC91" class="blob-code blob-code-inner js-file-line">PT2_FIXED_IP=<span class="pl-s"><span class="pl-pds">$(</span>neutron floatingip-list <span class="pl-k">|</span> grep <span class="pl-smi">$PT2_PORT_IP</span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L92" class="blob-num js-line-number" data-line-number="92"></td>
        <td id="LC92" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L93" class="blob-num js-line-number" data-line-number="93"></td>
        <td id="LC93" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> PT2_FIXED_IP <span class="pl-s"><span class="pl-pds">&quot;</span>Floating IP not assigned to policy target<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L94" class="blob-num js-line-number" data-line-number="94"></td>
        <td id="LC94" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L95" class="blob-num js-line-number" data-line-number="95"></td>
        <td id="LC95" class="blob-code blob-code-inner js-file-line">PT1_PORT_ID=<span class="pl-s"><span class="pl-pds">$(</span>gbp policy-target-show <span class="pl-smi">$PT1_ID</span> <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> port_id <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L96" class="blob-num js-line-number" data-line-number="96"></td>
        <td id="LC96" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L97" class="blob-num js-line-number" data-line-number="97"></td>
        <td id="LC97" class="blob-code blob-code-inner js-file-line">PT1_PORT_IP=<span class="pl-s"><span class="pl-pds">$(</span>neutron port-show <span class="pl-smi">$PT1_PORT_ID</span> <span class="pl-k">|</span> grep <span class="pl-s"><span class="pl-pds">&#39;</span> fixed_ips <span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $7}<span class="pl-pds">&#39;</span></span> <span class="pl-k">|</span> awk -F <span class="pl-s"><span class="pl-pds">&#39;</span>&quot;<span class="pl-pds">&#39;</span></span> <span class="pl-s"><span class="pl-pds">&#39;</span>{print $2}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L98" class="blob-num js-line-number" data-line-number="98"></td>
        <td id="LC98" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L99" class="blob-num js-line-number" data-line-number="99"></td>
        <td id="LC99" class="blob-code blob-code-inner js-file-line">PT1_FIXED_IP=<span class="pl-s"><span class="pl-pds">$(</span>neutron floatingip-list <span class="pl-k">|</span> grep <span class="pl-smi">$PT1_PORT_IP</span> <span class="pl-k">|</span> awk <span class="pl-s"><span class="pl-pds">&#39;</span>{print $4}<span class="pl-pds">&#39;</span></span> <span class="pl-pds">)</span></span></td>
      </tr>
      <tr>
        <td id="L100" class="blob-num js-line-number" data-line-number="100"></td>
        <td id="LC100" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L101" class="blob-num js-line-number" data-line-number="101"></td>
        <td id="LC101" class="blob-code blob-code-inner js-file-line">die_if_not_set <span class="pl-smi">$LINENO</span> PT1_FIXED_IP <span class="pl-s"><span class="pl-pds">&quot;</span>Floating IP not assigned to policy target<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L102" class="blob-num js-line-number" data-line-number="102"></td>
        <td id="LC102" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L103" class="blob-num js-line-number" data-line-number="103"></td>
        <td id="LC103" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L104" class="blob-num js-line-number" data-line-number="104"></td>
        <td id="LC104" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L105" class="blob-num js-line-number" data-line-number="105"></td>
        <td id="LC105" class="blob-code blob-code-inner js-file-line"><span class="pl-c">#############Cleanup###############</span></td>
      </tr>
      <tr>
        <td id="L106" class="blob-num js-line-number" data-line-number="106"></td>
        <td id="LC106" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L107" class="blob-num js-line-number" data-line-number="107"></td>
        <td id="LC107" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L108" class="blob-num js-line-number" data-line-number="108"></td>
        <td id="LC108" class="blob-code blob-code-inner js-file-line">gbp policy-target-delete <span class="pl-smi">$PT2_ID</span></td>
      </tr>
      <tr>
        <td id="L109" class="blob-num js-line-number" data-line-number="109"></td>
        <td id="LC109" class="blob-code blob-code-inner js-file-line">gbp policy-target-delete <span class="pl-smi">$PT1_ID</span></td>
      </tr>
      <tr>
        <td id="L110" class="blob-num js-line-number" data-line-number="110"></td>
        <td id="LC110" class="blob-code blob-code-inner js-file-line">gbp group-delete <span class="pl-smi">$PTG_ID</span></td>
      </tr>
      <tr>
        <td id="L111" class="blob-num js-line-number" data-line-number="111"></td>
        <td id="LC111" class="blob-code blob-code-inner js-file-line">gbp network-service-policy-delete <span class="pl-smi">$NSP_ID</span></td>
      </tr>
      <tr>
        <td id="L112" class="blob-num js-line-number" data-line-number="112"></td>
        <td id="LC112" class="blob-code blob-code-inner js-file-line">gbp nat-pool-delete <span class="pl-smi">$NAT_POOL_ID</span></td>
      </tr>
      <tr>
        <td id="L113" class="blob-num js-line-number" data-line-number="113"></td>
        <td id="LC113" class="blob-code blob-code-inner js-file-line">gbp external-segment-delete <span class="pl-smi">$EXT_SEGMENT_ID</span></td>
      </tr>
      <tr>
        <td id="L114" class="blob-num js-line-number" data-line-number="114"></td>
        <td id="LC114" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L115" class="blob-num js-line-number" data-line-number="115"></td>
        <td id="LC115" class="blob-code blob-code-inner js-file-line"><span class="pl-k">if</span> [ <span class="pl-s"><span class="pl-pds">&quot;</span><span class="pl-smi">$EXT_NET_TO_BE_CLEANED_UP</span><span class="pl-pds">&quot;</span></span> = <span class="pl-c1">true</span> ] <span class="pl-k">;</span> <span class="pl-k">then</span></td>
      </tr>
      <tr>
        <td id="L116" class="blob-num js-line-number" data-line-number="116"></td>
        <td id="LC116" class="blob-code blob-code-inner js-file-line">    neutron net-delete <span class="pl-smi">$EXT_NET_ID</span></td>
      </tr>
      <tr>
        <td id="L117" class="blob-num js-line-number" data-line-number="117"></td>
        <td id="LC117" class="blob-code blob-code-inner js-file-line"><span class="pl-k">fi</span></td>
      </tr>
      <tr>
        <td id="L118" class="blob-num js-line-number" data-line-number="118"></td>
        <td id="LC118" class="blob-code blob-code-inner js-file-line">
</td>
      </tr>
      <tr>
        <td id="L119" class="blob-num js-line-number" data-line-number="119"></td>
        <td id="LC119" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">set</span> +o xtrace</td>
      </tr>
      <tr>
        <td id="L120" class="blob-num js-line-number" data-line-number="120"></td>
        <td id="LC120" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>*********************************************************************<span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L121" class="blob-num js-line-number" data-line-number="121"></td>
        <td id="LC121" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>SUCCESS: End DevStack Exercise: <span class="pl-smi">$0</span><span class="pl-pds">&quot;</span></span></td>
      </tr>
      <tr>
        <td id="L122" class="blob-num js-line-number" data-line-number="122"></td>
        <td id="LC122" class="blob-code blob-code-inner js-file-line"><span class="pl-c1">echo</span> <span class="pl-s"><span class="pl-pds">&quot;</span>*********************************************************************<span class="pl-pds">&quot;</span></span></td>
      </tr>
</table>

  </div>

</div>

<a href="#jump-to-line" rel="facebox[.linejump]" data-hotkey="l" style="display:none">Jump to Line</a>
<div id="jump-to-line" style="display:none">
  <form accept-charset="UTF-8" action="" class="js-jump-to-line-form" method="get"><div style="margin:0;padding:0;display:inline"><input name="utf8" type="hidden" value="&#x2713;" /></div>
    <input class="linejump-input js-jump-to-line-field" type="text" placeholder="Jump to line&hellip;" autofocus>
    <button type="submit" class="btn">Go</button>
</form></div>

        </div>

      </div><!-- /.repo-container -->
      <div class="modal-backdrop"></div>
    </div><!-- /.container -->
  </div><!-- /.site -->


    </div><!-- /.wrapper -->

      <div class="container">
  <div class="site-footer" role="contentinfo">
    <ul class="site-footer-links right">
        <li><a href="https://status.github.com/" data-ga-click="Footer, go to status, text:status">Status</a></li>
      <li><a href="https://developer.github.com" data-ga-click="Footer, go to api, text:api">API</a></li>
      <li><a href="https://training.github.com" data-ga-click="Footer, go to training, text:training">Training</a></li>
      <li><a href="https://shop.github.com" data-ga-click="Footer, go to shop, text:shop">Shop</a></li>
        <li><a href="https://github.com/blog" data-ga-click="Footer, go to blog, text:blog">Blog</a></li>
        <li><a href="https://github.com/about" data-ga-click="Footer, go to about, text:about">About</a></li>
      <li><a href="https://help.github.com" data-ga-click="Footer, go to help, text:help">Help</a></li>

    </ul>

    <a href="https://github.com" aria-label="Homepage">
      <span class="mega-octicon octicon-mark-github" title="GitHub"></span>
</a>
    <ul class="site-footer-links">
      <li>&copy; 2015 <span title="0.03635s from github-fe121-cp1-prd.iad.github.net">GitHub</span>, Inc.</li>
        <li><a href="https://github.com/site/terms" data-ga-click="Footer, go to terms, text:terms">Terms</a></li>
        <li><a href="https://github.com/site/privacy" data-ga-click="Footer, go to privacy, text:privacy">Privacy</a></li>
        <li><a href="https://github.com/security" data-ga-click="Footer, go to security, text:security">Security</a></li>
        <li><a href="https://github.com/contact" data-ga-click="Footer, go to contact, text:contact">Contact</a></li>
    </ul>
  </div>
</div>


    <div class="fullscreen-overlay js-fullscreen-overlay" id="fullscreen_overlay">
  <div class="fullscreen-container js-suggester-container">
    <div class="textarea-wrap">
      <textarea name="fullscreen-contents" id="fullscreen-contents" class="fullscreen-contents js-fullscreen-contents" placeholder=""></textarea>
      <div class="suggester-container">
        <div class="suggester fullscreen-suggester js-suggester js-navigation-container"></div>
      </div>
    </div>
  </div>
  <div class="fullscreen-sidebar">
    <a href="#" class="exit-fullscreen js-exit-fullscreen tooltipped tooltipped-w" aria-label="Exit Zen Mode">
      <span class="mega-octicon octicon-screen-normal"></span>
    </a>
    <a href="#" class="theme-switcher js-theme-switcher tooltipped tooltipped-w"
      aria-label="Switch themes">
      <span class="octicon octicon-color-mode"></span>
    </a>
  </div>
</div>



    
    

    <div id="ajax-error-message" class="flash flash-error">
      <span class="octicon octicon-alert"></span>
      <a href="#" class="octicon octicon-x flash-close js-ajax-error-dismiss" aria-label="Dismiss error"></a>
      Something went wrong with that request. Please try again.
    </div>


      <script crossorigin="anonymous" src="https://assets-cdn.github.com/assets/frameworks-808fcfcd63c9ecba3e84453f540cb1cbafde48c6b30c1d51ebd4e67e88ff66bd.js"></script>
      <script async="async" crossorigin="anonymous" src="https://assets-cdn.github.com/assets/github/index-4f888c77edb689a0c50e2edbc2d7ae11518355eff0bfeac3ab0a110ca10eddf9.js"></script>
      
      
  </body>
</html>

