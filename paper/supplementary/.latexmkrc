# Find the shared ../refs.bib (bibtex runs from the out dir, so use an absolute path).
use Cwd qw(abs_path);
$ENV{'BIBINPUTS'} = abs_path('..') . ':' . ($ENV{'BIBINPUTS'} // '');
