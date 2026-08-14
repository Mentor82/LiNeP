file(REMOVE_RECURSE
  "liblinep.dll"
  "liblinep.dll.a"
  "liblinep.dll.manifest"
  "liblinep.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/linep.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
