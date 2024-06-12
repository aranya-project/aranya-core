#!/usr/bin/env perl

use strict;
use warnings;
use List::MoreUtils qw(uniq);

my $input_file = "policy.pest";
my $output_file = "keywords.rs";

# Read the contents of the input file
open my $input_fh, '<', $input_file or die "Could not open file '$input_file': $!";
my $input_content = do { local $/; <$input_fh> };
close $input_fh;

my @keywords;

# Split the input content into an array of lines
my @lines = split /\n/, $input_content;

LINE: foreach my $line (@lines) {
    # Skip the line if it starts with "//"
    next if $line =~ /^\/\//;
    
    # Extract quoted strings including embedded quotes escaped with backslashes and escaped backslashes
    while ($line =~ /"((?:\\\\|\\"|[^"])*)"/g) {
        my $keyword = $1;
        
        # Remove non-alphanumeric and non-underscore characters from the keyword
        $keyword =~ s/[^A-Za-z_]//g;
        
        # Skip the keyword if it is a single character. This handles avoiding keywords that we don't want such as "x", "_", or "n"
        next if length($keyword) == 1;
        
        # Add the keyword to the @keywords array if it's not empty
        push @keywords, $keyword if $keyword;
    }


}

# Add 'envelope' and 'this' to the @keywords array
push @keywords, 'envelope', 'this';

# Remove duplicate keywords and sort them case-insensitively
@keywords = sort { lc($a) cmp lc($b) } uniq(@keywords);

# Count the number of keywords
my $num_keywords = scalar @keywords;

# Write the keywords to the Rust file
open my $output_fh, '>', $output_file or die "Could not open file '$output_file': $!";

print $output_fh "// This file contains the extracted keywords from policy.pest from keyword_extraction.pl\n\n";
print $output_fh "pub const KEYWORDS: [&str; $num_keywords] = [\n";

foreach my $keyword (@keywords) {
    print $output_fh "    \"$keyword\",\n";
}

print $output_fh "];\n";

close $output_fh;

print "Keywords extracted and saved to $output_file\n";