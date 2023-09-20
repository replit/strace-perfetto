{ pkgs }: {
    deps = [];
    devOnly = {
          deps = [
              pkgs.go
              pkgs.strace
          ];
    };
}