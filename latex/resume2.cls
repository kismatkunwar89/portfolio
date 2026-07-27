% resume2.cls - Modern clean resume class
\ProvidesClass{resume2}
\LoadClass[10pt,letterpaper]{article}

\usepackage[parfill]{parskip}
\usepackage{array}
\usepackage{ifthen}
\usepackage{enumitem}
\usepackage{xcolor}
\usepackage{titlesec}
\usepackage{fontenc}

\pagestyle{empty}
\setlength{\tabcolsep}{0em}

% Section formatting - bold uppercase with full-width rule below
\titleformat{\section}
  {\large\bfseries\uppercase}
  {}{0em}{}
  [\titlerule]
\titlespacing{\section}{0pt}{4pt}{2pt}

% Subsection for job title / org lines
\titleformat{\subsection}[runin]
  {\bfseries}
  {}{0em}{}
\titlespacing{\subsection}{0pt}{4pt}{2pt}

% Name command
\newcommand{\name}[1]{\def\@name{#1}}
\newcommand{\contact}[1]{\def\@contact{#1}}

\newcommand{\makeheader}{
  {\LARGE\bfseries \@name}\\[2pt]
  \@contact
  \vspace{4pt}
  \hrule
  \vspace{6pt}
}
