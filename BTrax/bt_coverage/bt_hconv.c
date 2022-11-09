/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_hconv.c - coverage output to html converter                           */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2010                         */
/*             Authors: Yumiko Sugita (yumiko.sugita.yf@hitachi.com),        */
/*                      Satoshi Fujiwara (sa-fuji@sdl.hitachi.co.jp)         */
/*                                                                           */
/*  This program is free software; you can redistribute it and/or modify     */
/*  it under the terms of the GNU General Public License as published by     */
/*  the Free Software Foundation; either version 2 of the License, or        */
/*  (at your option) any later version.                                      */
/*                                                                           */
/*  This program is distributed in the hope that it will be useful,          */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            */
/*  GNU General Public License for more details.                             */
/*                                                                           */
/*  You should have received a copy of the GNU General Public License        */
/*  along with this program; if not, write to the Free Software              */
/*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111 USA      */
/*****************************************************************************/

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include "bt_ar_parse.h"
#include "bt_hconv.h"
#include <direct.h>

/*
 * When the object contains debugging information, we need to create the source
 * code html.
 * The source line number of the result of the coverage check has the
 * possibility of appearing at random when it compiled with optimization.
 * Moreover, there is a possibility that two or more branches are included in
 * the same source line, too.
 * Therefore, we first create the execute-type per line array, then create the
 * source html by merging it with source file.
 */

#define T_NONE		0
#define T_NOT_EXECUTED	1
#define T_EXECUTED	2
#define T_UNKNOWN	3

/*-----------------------------------------------------------------------------
 *  output html
 *-----------------------------------------------------------------------------
 */
#define TREE_HTML_PATH	"each/__btrax_ftree__.html"

#define COLOR_OK	"#00ff00"
#define COLOR_HT	"#ffff00"
#define COLOR_NT	"#ff0000"
#define COLOR_ALREADY	"#a9a9a9"
#define COLOR_UN	COLOR_HT
#define COLOR_WT	"#ffffff"

#define COLOR_BOTH_OK	"#bbffbb"
#define COLOR_BOTH_HT	"#fffacd"
#define COLOR_BOTH_NT	"#ffcccc"
#define COLOR_DBL_NAME	"#999999"

#define JS_TREE_MENU	"tree_menu.js"
#define JS_BOTH_OPEN	"both_open_and_scrl.js"

#define BLANK_SRC1	"src/__s1.html"
#define BLANK_SRC2	"src/__s2.html"

enum {
	HEAD_TYPE_NORMAL,
	HEAD_TYPE_JS,
	HEAD_TYPE_JQUERY,
	HEAD_TYPE_SRC,
};

typedef int (*f_out_html_file)(struct cov_out_data *dt, FILE *f);

static int out_html_file(struct cov_out_data *dt, char *path,
			 f_out_html_file func)
{
	char buf[PATH_MAX + 1];
	FILE *f;
	int rc;
	errno_t err;

	buf[PATH_MAX] = '\0';
	_snprintf_s(buf, PATH_MAX, PATH_MAX - 1, "%s/%s", dt->outdir, path);
	err = fopen_s(&f, buf, "w");
	if (err) {
		//fprintf(stderr, "%s can't open.(%s)\n", buf, strerror(errno));
		return FAILURE;
	}
	rc = func(dt, f);
	if (rc == FAILURE)
		return rc;
	fclose(f);
	return SUCCESS;
}

static int __out_tree_menu_js(struct cov_out_data *dt, FILE *f)
{
	fprintf(f,
		"function treeMenu(tName) {\n" \
		"\ttMenu = document.all[tName].style;\n" \
		"\tif (tMenu.display == 'none') tMenu.display = 'block';\n" \
		"\telse tMenu.display = 'none'\n" \
		"}\n");
	return SUCCESS;
}
#define out_tree_menu_js(dt) \
	out_html_file((dt), JS_TREE_MENU, __out_tree_menu_js)

static int __out_both_open_and_scrl_js(struct cov_out_data *dt, FILE *f)
{
	fprintf(f,
		"function bothOpen(x1, x2) {\n" \
	        "\twindow.open(x1, \"s1\");\n" \
	        "\twindow.open(x2, \"s2\");\n" \
	        "\tparent.s1.startSetTop();\n" \
	        "\tparent.s2.startSetTop();\n" \
	        "}\n" \
		"function syncScroll(e) {\n" \
	        "\tif (e.charCode == 85 || e.charCode == 117) {\n" \
	        "\t\tparent.s1.scrollBy(0,10);\n" \
	        "\t\tparent.s2.scrollBy(0,10);\n" \
	        "\t} else if (e.charCode == 68 || e.charCode == 100) {\n" \
	        "\t\tparent.s1.scrollBy(0,-10);\n" \
	        "\t\tparent.s2.scrollBy(0,-10);\n" \
	        "\t}\n" \
	        "}\n");
	return SUCCESS;
}
#define out_both_open_and_scrl_js(dt) \
	out_html_file((dt), JS_BOTH_OPEN, __out_both_open_and_scrl_js)

static void out_html_header(FILE *f, char *doctype, char *title, int type,
			    char *js_path)
{
	fprintf(f,
		"%s\n" \
		"<html lang=\"en\">\n" \
		"<head>\n" \
		"<meta http-equiv=\"Content-Type\" content=\"text/html;" \
		" charset=ISO-8859-1\">\n" \
		"<meta http-equiv=\"Content-Style-Type\"" \
		" content=\"text/css\">\n",
		doctype);
	if (type == HEAD_TYPE_JS) {
		fprintf(f,
			"<meta http-equiv=\"Content-Script-Type\"" \
			" content=\"text/css\">\n" \
			"<script type=\"text/javascript\"" \
			" src=\"%s\"></script>\n",
			js_path);
	}
	if (type == HEAD_TYPE_JQUERY) {
#ifdef _OUT_TABLE
		fprintf(f, "<link rel=\"stylesheet\" href=\"dist/themes/default/style.min.css\" />\n");
		fprintf(f,		
			"<style>\n" \
			"table.paths, table.paths td, table.paths th {\n" \
			"	border-collapse:collapse;\n" \
			"	border:1px solid black;\n" \
			"}\n" \
			"table.paths tr.fname {\n" \
			"	font-weight:bold;\n" \
			"}\n" \
			"</style>\n");
#endif
/*
		fprintf(f,
			"<meta http-equiv=\"Content-Script-Type\"" \
			" content=\"text/css\">\n" \
			"<script type=\"text/javascript\"" \
			" src=\"%s\"></script>\n",
			js_path);
*/
		fprintf(f, "<script src=\"dist/lib/jquery.js\" type=\"text/javascript\"></script>\n");
		fprintf(f, "<script src=\"dist/lib/jquery-ui.custom.js\" type=\"text/javascript\"></script>\n");
		fprintf(f, "<link href=\"dist/skin-win8/ui.fancytree.css\" rel=\"stylesheet\" type=\"text/css\">\n");
		fprintf(f, "<script src=\"dist/lib/jquery.fancytree.js\" type=\"text/javascript\"></script>\n");
		fprintf(f,
			"<script>\n" \
			"$(function() {\n"
#ifdef _OUT_TABLE
			"	$('tr.fname').click(function(){\n" \
			"		if (this.id.length) {\n" \
			"			var s = $(this).nextUntil('tr[end=' + this.id + ']');\n" \
			"			if ($(this).next().css('display') == 'none') {\n" \
			"				$(this).nextUntil('tr[end=' + this.id + ']').show();\n" \
			"				s.last().next().show();\n" \
			"			} else {\n" \
			"				$(this).nextUntil('tr[end=' + this.id + ']').hide();\n" \
			"				s.last().next().hide();\n" \
			"			}\n" \
			"		} else {\n" \
			"			$(this).nextUntil('tr.fname').toggle();\n" \
			"		}\n" \
			"	});\n"
#else
			"	$('#pathstree').fancytree({\n" \
			"		activate: function(event, data) {\n" \
			"			var node = data.node;\n" \
			"			if (!node.isFolder()) {\n" \
			"				var panode = node.parent;\n" \
			"				if (panode.tooltip) {\n" \
			"					var idx, cur_line, last_line = 0, lines = '';\n" \
			"					var childnodes = panode.getChildren();\n" \
			"					var srcfile = panode.tooltip.substring(panode.tooltip.indexOf('\\\\'));\n" \
			"					for (var i = 0; i < childnodes.length; i++) {\n" \
			"						idx = childnodes[i].title.indexOf(':');\n" \
			"						if (idx > -1) {\n" \
			"							cur_line = parseInt(childnodes[i].title.substring(idx + 1));\n" \
			"							if (childnodes[i].data.to) {\n" \
			"								last_line = cur_line;\n" \
			"							} else {\n" \
			"								if (last_line && ((last_line + 1) < cur_line)) {\n" \
			"									for (var j = last_line + 1; j < cur_line; j++) {\n" \
			"										lines += j.toString() + ',';\n" \
			"									}\n" \
			"								}\n" \
			"								last_line = 0;\n" \
			"							}\n" \
			"							lines += cur_line.toString() + ',';\n" \
			"						} else {\n" \
			"							last_line = 0;\n" \
			"						}\n" \
			"					}\n" \
			"					idx = node.title.indexOf(':');\n" \
			"					window.open('src' + srcfile + '.html?' + lines + '#' + node.title.substring(idx + 1), 'src');\n" \
			"				}\n" \
			"			}\n" \
			"		}\n" \
			"	});\n"
#endif
			"});\n" \
			"</script>\n");
	}
	if (type == HEAD_TYPE_SRC) {
		//fprintf(f, "<script src=\"/Projects/bt_analyzer/bt_analyzer/out/dist/lib/jquery.js\" type=\"text/javascript\"></script>\n");
		fprintf(f, 
			"<script>\n" \
			"function resetall() {\n" \
			"  var idxstart = document.URL.indexOf('?');\n" \
			"  var idxend = document.URL.indexOf('#');\n" \
			"  //alert(idxstart);\n" \
			"  if (idxstart != -1) {\n" \
			"    if (idxend == -1) idxend = document.URL.length;\n" \
			"    var coloredary = document.URL.substring(idxstart + 1, idxend).split(',');\n" \
			"    var lineary = document.getElementsByTagName('a');\n" \
			"    var color, name;\n" \
			"    for (var i = 0; i < lineary.length; i++) {\n" \
			"      color = 0;\n" \
			"      name = lineary[i].getAttribute('name');\n" \
			"      for (var j =0; j < coloredary.length; j++) {\n" \
			"        if (coloredary[j] == name) {\n" \
			"          color = 1;\n" \
			"          break;\n" \
			"        }\n" \
			"      }\n" \
			"      lineary[i].style.backgroundColor = (color ? '#00ff00':'#ffffff');\n" \
			"    }\n" \
			"  }\n" \
			"}\n" \
			"</script>\n");
	}
	fprintf(f,
		"<title>%s</title>\n" \
		"</head>\n",
		title);
}

static void out_html_frame_header(FILE *f, char *title)
{
	out_html_header(f,
			"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01" \
			" Frameset//EN\">",
			title, HEAD_TYPE_NORMAL, NULL);
}

static void out_html_normal_header(FILE *f, char *title, int type,
				   char *js_path)
{
	out_html_header(f,
			"<!DOCTYPE html>",
			title, type, js_path);
	//"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01" \
	//" Transitional//EN\">",
}

static int __out_top_html(struct cov_out_data *dt, FILE *f)
{
	out_html_frame_header(f, "Insyde - Code Coverage Result");
	//fprintf(f,
	//	"<frameset title=\"all\" rows=\"34,*\">\n" \
	//	"  <frame title=\"title\" src=\"./title.html\"" \
	//	" scrolling=\"no\" noresize>\n");
	if (dt->chk_type == CHK_DIFF)
		fprintf(f,
			"  <frameset title=\"right\" cols=\"30%%,*\">\n" \
			"    <frameset title=\"left\" rows=\"40%%,*\">\n" \
			"      <frame title=\"summary\" name=\"summary\"" \
			" src=\"./summary.html\">\n" \
			"      <frame title=\"each\" name=\"each\">\n" \
			"    </frameset>\n" \
			"    <frameset title=\"src\" cols=\"50%%,*\">\n" \
			"      <frame title=\"s1\" name=\"s1\">\n" \
			"      <frame title=\"s2\" name=\"s2\" noresize>\n" \
			"    </frameset>\n");
			//"  </frameset>\n");
	else
		fprintf(f,
			"<frameset title=\"right\" cols=\"50%%,*\">\n" \
			"  <frameset title=\"left\" rows=\"40%%,*\">\n" \
			"    <frame title=\"summary\" name=\"summary\"" \
			" src=\"./summary.html\">\n" \
			"    <frame title=\"each\" name=\"each\">\n" \
			"  </frameset>\n" \
			"  <frame title=\"src\" name=\"src\">\n");
			//"  </frameset>\n");
	fprintf(f,
		"  <noframes><body><p>use frame supported browser</p></body>" \
		"</noframes>\n" \
		"</frameset>\n" \
		"</html>\n");
	return SUCCESS;
}
static int __out_top2_html(struct cov_out_data *dt, FILE *f)
{
	out_html_frame_header(f, "Insyde - Execution Paths Result");
	//fprintf(f,
	//	"<frameset title=\"all\" rows=\"34,*\">\n" \
	//	"  <frame title=\"title2\" src=\"./title2.html\"" \
	//	" scrolling=\"no\" noresize>\n");
	fprintf(f,
		"<frameset title=\"right\" cols=\"30%%,*\">\n" \
		"  <frame title=\"paths\" name=\"paths\"" \
		" src=\"./execpaths.html\">\n" \
		"  <frame title=\"src\" name=\"src\">\n");
		//"  </frameset>\n");
	fprintf(f,
		"  <noframes><body><p>use frame supported browser</p></body>" \
		"</noframes>\n" \
		"</frameset>\n" \
		"</html>\n");
	return SUCCESS;
}

#define out_top_html(dt) \
	out_html_file((dt), "top.html", __out_top_html)
#define out_top2_html(dt) \
	out_html_file((dt), "top2.html", __out_top2_html)

static int __out_title_html(struct cov_out_data *dt, FILE *f)
{
	out_html_normal_header(f, "title", HEAD_TYPE_NORMAL, NULL);
	fprintf(f,
		"<body style=\"background-color:silver\">\n" \
		"<p style=\"font-size:16pt; font-weight:bold;" \
		" text-align:center\">\n" \
		"<span style=\"color:#0000ff\">Insyde</span> Code Coverage\n" \
		"<span style=\"color:#ff0000\">R</span>e" \
		"<span style=\"color:#ffff00\">s</span>u" \
		"<span style=\"color:#00ff00\">l</span>t\n" \
		"</p>\n" \
		"</body></html>\n");
	return SUCCESS;
}
static int __out_title2_html(struct cov_out_data *dt, FILE *f)
{
	out_html_normal_header(f, "title2", HEAD_TYPE_NORMAL, NULL);
	fprintf(f,
		"<body style=\"background-color:silver\">\n" \
		"<p style=\"font-size:16pt; font-weight:bold;" \
		" text-align:center\">\n" \
		"<span style=\"color:#0000ff\">Insyde</span> Execution Paths\n" \
		"<span style=\"color:#ff0000\">R</span>e" \
		"<span style=\"color:#ffff00\">s</span>u" \
		"<span style=\"color:#00ff00\">l</span>t\n" \
		"</p>\n" \
		"</body></html>\n");
	return SUCCESS;
}
#define out_title_html(dt) \
	out_html_file((dt), "title.html", __out_title_html)
#define out_title2_html(dt) \
	out_html_file((dt), "title2.html", __out_title2_html)

static int __out_blank_html(struct cov_out_data *dt, FILE *f)
{
	out_html_normal_header(f, "title", HEAD_TYPE_NORMAL, NULL);
	fprintf(f,
		"<body style=\"font-size:8pt\"><pre>\n"\
		"</pre>\n" \
		"</body></html>\n");
	return SUCCESS;
}
#define out_blank_html(dt) \
	out_html_file((dt), BLANK_SRC1, __out_blank_html)

static char* get_rel_path(struct cov_out_data *dt, int side, char cov_type)
{
	char *name;

	// If there are some ELFs which have the same basename in each 'r2p',
	// 'cur_ELFname' is the full-path. So, we have to convert '/' to '_'.
	name = conv_slash2underscore(dt->cur_ELFname, TRUE);
	if (cov_type == 'f' || dt->chk_type != CHK_DIFF)
		_snprintf_s(dt->abs_path, PATH_MAX, PATH_MAX - 1, "%s/each/%s.%c.html",
			 dt->outdir, name, cov_type);
	else {
		struct range_to_name *r2n = dt->r2p[side]->r2n;
		char *diff_sep;

		if (dt->chk_type == CHK_DIFF && is_lib_or_app(r2n)) {
			diff_sep = side == 0 ? "1_" : "2_";
			// We don't want to overwrite summary html by the same
			// ELF, so if the 'r2n' is a library or an application,
			// we create the html which identified by 'L1' or 'L2'.
			_snprintf_s(dt->abs_path, PATH_MAX, PATH_MAX - 1, "%s/each/%s%s.%c.html",
				 dt->outdir, diff_sep, name, cov_type);
		} else
			_snprintf_s(dt->abs_path, PATH_MAX, PATH_MAX - 1,"%s/each/%s.%c.%s.html",
				 dt->outdir, name, cov_type,
				 dt->r2p[side]->r2i.uname_r);
	}
	free(name);
	return dt->abs_path + strlen(dt->outdir) + 1;
}

static void open_html(struct cov_out_data *dt)
{
	errno_t err;

	err = fopen_s(&dt->cur_out, dt->abs_path, "w");
	if (err) {
		//fprintf(stderr, "%s can't open.(%s)\n",
		//	dt->abs_path, strerror(errno));
		exit(1);
	}
}

static void close_html(struct cov_out_data *dt)
{
	if (dt->cur_out) {
		fclose(dt->cur_out);
		dt->cur_out = NULL;
	}
}

static void out_summary_html_start(struct cov_out_data *dt)
{
	out_html_normal_header(dt->summary_out, "summary", HEAD_TYPE_NORMAL,
			       NULL);
	fprintf(dt->summary_out, "<body>\n");
	if (dt->chk_type == CHK_SINGLE)
		fprintf(dt->summary_out,
			"<table summary=\"summary\" border=\"1\">\n" \
			"  <tr><th rowspan=\"2\">module/driver package</th><th colspan=\"3\">" \
			"coverage</th></tr>\n" \
			"  <tr><th>function</th><th>branch</th><th>state</th>" \
			"</tr>\n");
	else
		fprintf(dt->summary_out,
			"<b>Coverage compare:<br></b>\n" \
			"<b>L1(%s)</b> and <b>L2(%s)</b><br>\n" \
			"<table summary=\"summary\" border=\"1\">\n" \
			"  <tr><th rowspan=\"3\">name</th><th colspan=\"6\">" \
			"coverage</th></tr>\n" \
			"  <tr><th colspan=\"2\">function</th>" \
			"<th colspan=\"2\">branch</th><th colspan=\"2\">state" \
			"</th></tr>\n" \
			"  <tr><th>L1</th><th>L2</th><th>L1</th><th>L2</th>" \
			"<th>L1</th><th>L2</th></tr>\n",
			dt->r2p[0]->r2i.uname_r, dt->r2p[1]->r2i.uname_r);
}

void out_summary_html_name(struct cov_out_data *dt)
{
	fprintf(dt->summary_out, "  <tr><td>%s</td>\n", dt->cur_ELFname);
}

void out_summary_html_func(struct cov_out_data *dt, int side,
			   long n_func, long n_func_all)
{
	char *rel_path;

	rel_path = get_rel_path(dt, side, 'f');
	fprintf(dt->summary_out,
		"    <td nowrap align=\"right\"><a href=\"%s\" target=\"each\""\
		" title=\"%s\">%.2f%%</a><br>(%ld/%ld)</td>\n",
		rel_path, rel_path, get_percent(n_func, n_func_all),
		n_func, n_func_all);
}

void out_summary_html_branch(struct cov_out_data *dt, int side,
			     long n_br_ok, long n_br_uk,
			     long n_br_ht, long n_br_nt,
			     long n_br_all, long n_uk_all)
{
	char *rel_path;

	rel_path = get_rel_path(dt, side, 'b');
	if (n_br_all)
		fprintf(dt->summary_out,
			"    <td nowrap align=\"right\"><a href=\"%s\"" \
			" target=\"each\" title=\"%s\">%.2f%%(%.2f%%)</a><br>" \
			"(OK:%ld,HT:%ld,NT:%ld/%ld (UK:%ld/%ld))</td>\n",
			rel_path, rel_path,
			get_percent(n_br_ok * 2 + n_br_ht, n_br_all),
			get_percent(n_br_uk, n_uk_all),
			n_br_ok, n_br_ht, n_br_nt, n_br_all,
			n_br_uk, n_uk_all);
	else
		fprintf(dt->summary_out,
			"    <td nowrap align=\"right\">----</td>\n");
}

void out_summary_html_state(struct cov_out_data *dt, int side,
			    long n_ok, long n_states)
{
	char *rel_path;

	rel_path = get_rel_path(dt, side, 's');
	fprintf(dt->summary_out,
		"    <td nowrap align=\"right\"><a href=\"%s\" target=\"each\""\
		" title=\"%s\">%.2f%%</a><br>(%ld/%ld)</td>",
		rel_path, rel_path, get_percent(n_ok, n_states),
		n_ok, n_states);
	if (side != 0 || dt->chk_type == CHK_SINGLE)
		fprintf(dt->summary_out, "</tr>\n");
}

static void out_summary_html_end(struct cov_out_data *dt, int limit_by_funcs)
{
	fprintf(dt->summary_out, "</table>\n");
	if (limit_by_funcs && dt->chk_type == CHK_SINGLE)
		fprintf(dt->summary_out,
			"<a href=\"%s\" target=\"each\" title=\"ftree\">" \
			"View function tree.</a>",
			TREE_HTML_PATH);
	fprintf(dt->summary_out, "</body></html>\n");
}

static struct src_info* chk_src_line_type(struct cov_out_data*, int side,
					  const char*, const char*, size_t, char);
static char* get_src_html_path(struct cov_out_data*, struct src_info*, int,
			       bool_t);

static int chk_func_src_type(struct cov_out_data *dt, int side, UINT64 addr)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;
	char *cdir = NULL, *src, *func; //, *tmp;
	//int type,
	int rc1, rc2; //, ln1, ln2; //lastln, 
	size_t offset;
	//struct src_info *info;
	//char *ref = NULL, *p;
	struct path *p;
	struct branch_node *cur_node;
	INT i;
	DWORD j;
	//unsigned long addr1, addr2;
	//int fallthrough;
	DWORD line1, line2;

	i = r2n->num_path_array;
	p = find_path_by_addr(r2n, &i, addr);
	if (!p)
		return FAILURE;
	cur_node = p->exec_node;
	//fallthrough = 0;
	//ln1 = ln2 = 0; //= lastln
	while (cur_node) {
		src = NULL;
		line1 = line2 = 0;
		if (cur_node->addr_to)
			rc1 = get_source_info(&r2n->bi, cur_node->addr_to, &cdir, &src, &func, &line1, &offset);
		if (cur_node->addr_from)
			rc2 = get_source_info(&r2n->bi, cur_node->addr_from, &cdir, &src, &func, &line2, &offset);
		if (src && (line1 || line2)) {
			/*ln2 = ln1;
			if (fallthrough) {
				ln1 = lastln;
			} else {
				if (cur_node->isTo) {
					cur_node = cur_node->next;
					if (cur_node) {
						addr2 = cur_node->addr;
						rc2 = get_source_info(&r2n->bi, addr2, &cdir, &src, &func, &ln2, &offset, FALSE);
					}
				}
			}
			*/

			if (line1 && line2 && (line1 <= line2)) {
				for (j = line1; j <= line2; j++)
					chk_src_line_type(dt, side, cdir, src, j, T_EXECUTED);
			} else {
				if (line1) chk_src_line_type(dt, side, cdir, src, line1, T_EXECUTED);
				if (line2) chk_src_line_type(dt, side, cdir, src, line2, T_EXECUTED);
			}
		}
		else
		{
			return FAILURE;
		}

		//if (cur_node) {
			//fallthrough = cur_node->isTo ? 1:0;
			//lastln = ln2;
			cur_node = cur_node->next;
		//}
	}
	
	return SUCCESS;
}

static int get_fname_and_ref_str(struct cov_out_data *dt, int side,
				 UINT64 addr, int type,
				 char buf[MAX_LINE_LEN],
				 char **p_fname, char **p_ref)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;
	char *cdir = NULL, *src, *func; //, *tmp;
	int len, left, rc; //ln, 
	size_t offset;
	struct src_info *info;
	char *ref = NULL, *p;
	DWORD line;

	rc = get_source_info(&r2n->bi, addr, &cdir, &src, &func, &line, &offset);
	//rc = addr_to_func_name_and_offset(&r2n->bi, addr, &func, &offset);
	if (rc == SUCCESS) {
		//get_source_info(&r2n->bi, addr, &cdir, &src, &tmp, &ln, TRUE);
		if (src && line &&
		    (info = chk_src_line_type(dt, side, cdir, src, line, type)))
			ref = get_src_html_path(dt, info, side, TRUE);
		if (offset)
			len = _snprintf_s(buf, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s+" PF_LH_NC,
				       func, offset);
		else
			len = _snprintf_s(buf, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s", func);
	} else
		len = _snprintf_s(buf, MAX_LINE_LEN, MAX_LINE_LEN - 1, "0x%08llx", addr);
	if (len >= MAX_LINE_LEN)
		goto ERR;
	*p_fname = buf;
	*p_ref = NULL;
	if (!ref)
		return SUCCESS;
	p = buf + len + 1;
	left = MAX_LINE_LEN - len - 1;
	len = _snprintf_s(p, left, left - 1, "%s#%d", ref, line);
	if (len >= left)
		goto ERR;
	*p_ref = p;
	return SUCCESS;
ERR:
	//fprintf(stderr, "MAX_LINE_LEN too short.\n");
	return FAILURE;
}

static void get_func_each_init_value(struct cov_out_data *dt,
				     struct func_chk *fc, struct func_chk *fc2,
				     UINT64 *addr, UINT64 *addr2,
				     unsigned long *cnt, unsigned long *cnt2,
				     bool_t *is_double_name)
{
	if (fc) {
		*addr = fc->dest.addr;
		*cnt = fc->cnt;
		*is_double_name = IS_SAME_NAME_EXISTS_FC(fc);
	} else {
		*addr = UNKNOWN_BADDR;
		*cnt = 0;
	}
	if (fc2) {
		*addr2 = fc2->dest.addr;
		*cnt2 = fc2->cnt;
		*is_double_name = IS_SAME_NAME_EXISTS_FC(fc2);
	} else {
		*addr2 = UNKNOWN_BADDR;
		*cnt2 = 0;
	}
}

void __out_func_html_each(struct cov_out_data *dt,
			  struct func_chk *fc, struct func_chk *fc2,
			  long *same, long *diff)
{
	FILE *out = dt->cur_out;
	char *color, buf[2][MAX_LINE_LEN], *p_fname, *p_ref, *p_ref2;
	int type, type2 = T_NONE;
	bool_t is_exec, is_exec2, is_double_name = FALSE;
	UINT64 addr, addr2;
	DWORD cnt, cnt2;
	//int i;

	get_func_each_init_value(dt, fc, fc2, &addr, &addr2, &cnt, &cnt2,
				 &is_double_name);
	is_exec = cnt != 0;
	type = is_exec ? T_EXECUTED : T_NOT_EXECUTED;
	if (dt->chk_type == CHK_SINGLE)
		color = is_exec ? COLOR_OK : COLOR_NT; //COLOR_WT;
	else {
		is_exec2 = cnt2 != 0;
		if (same && diff) {
			if (is_exec != is_exec2)
				(*diff)++;
			else
				(*same)++;
			return;
		}
		if (is_double_name)
			color = COLOR_DBL_NAME;
		else if (is_exec == is_exec2)
			color = is_exec2 ? COLOR_BOTH_OK : COLOR_BOTH_NT;
		else
			color = is_exec2 ? COLOR_OK : COLOR_NT;
		type2 = is_exec2 ? T_EXECUTED : T_NOT_EXECUTED;
	}
	p_ref = p_ref2 = NULL;
	if (fc) {
		if (get_fname_and_ref_str(dt, 0, addr, type, buf[0],
					  &p_fname, &p_ref) == FAILURE)
			return;

		// Get path and check source line type
		chk_func_src_type(dt, 0, addr);
	}
	if (dt->chk_type != CHK_SINGLE && fc2) {
		if (get_fname_and_ref_str(dt, 1, addr2, type2, buf[1],
					  &p_fname, &p_ref2) == FAILURE)
			return;
	}
	fprintf(out, "<tr><td bgcolor=\"%s\">", color);
	if (dt->chk_type == CHK_DIFF) {
		if (!p_ref && !p_ref2)
			fprintf(out, "%s", p_fname);
		else
			fprintf(out,
				"<a href=\"javascript:bothOpen('%s', '%s')\">" \
				"%s</a>",
				p_ref ? p_ref : "../" BLANK_SRC1,
				p_ref2 ? p_ref2 : "../" BLANK_SRC2,
			       	p_fname);
	} else {
		if (p_ref)
			fprintf(out, "<a href=\"%s\" target=\"src\">%s</a>",
				p_ref, p_fname);
		else
			fprintf(out, "%s", p_fname);
	}
	fprintf(out, "</td>");
	if (fc)
		fprintf(out, "<td align=\"right\">%ld</td>", cnt);
	else
		fprintf(out, "<td align=\"right\"></td>");
	if (dt->chk_type == CHK_SINGLE) {
		if (dt->limit_by_funcs)
			fprintf(out, "<td align=\"right\">%d</td>",
				fc->tree_weight);
	} else {
		if (fc2)
			fprintf(out, "<td align=\"right\">%ld</td>", cnt2);
		else
			fprintf(out, "<td align=\"right\"></td>");
	}
	fprintf(out, "</tr>\n");
}

void out_func_html_each(struct cov_out_data *dt, struct func_chk *fc)
{
	__out_func_html_each(dt, fc, NULL, NULL, NULL);
}

void out_func_html_each2(struct cov_out_data *dt,
			 struct func_chk *fc1, struct func_chk *fc2,
			 long *same, long *diff)
{
	__out_func_html_each(dt, fc1, fc2, same, diff);
}

void out_func_html_end(struct cov_out_data *dt)
{
	fprintf(dt->cur_out,
		"</table>\n" \
		"</body></html>\n");
	close_html(dt);
}

static inline void out_diff_same_diff(struct cov_out_data *dt,
				      unsigned long same, unsigned long diff)
{
	fprintf(dt->cur_out, "<b>same:</b> %.2f%%, <b>diff:</b> %.2f%%<br>\n",
		get_percent(same, same + diff), get_percent(diff, same + diff));
}

void out_branch_html_start(struct cov_out_data *dt, long same, long diff)
{
	char title[MAX_LINE_LEN + 1];

	open_html(dt);
	title[MAX_LINE_LEN] = '\0';
	sprintf_s(title, MAX_LINE_LEN, "%s branch coverage", dt->cur_ELFname);
	out_html_normal_header(dt->cur_out, title, HEAD_TYPE_NORMAL, NULL);
	fprintf(dt->cur_out, "<body>\n");
	if (dt->chk_type == CHK_SAME) {
		out_diff_same_diff(dt, same, diff);
		fprintf(dt->cur_out,
			"<table summary=\"%s\" border=\"1\"><tr>\n" \
			"  <th rowspan=\"3\">base</th>\n" \
			"  <th colspan=\"3\">branch</th>\n" \
			"  <th colspan=\"3\">next</th></tr>\n" \
			"  <tr>\n" \
			"  <th rowspan=\"2\">address</th><th colspan=\"2\">" \
			"cnt</th>\n" \
			"  <th rowspan=\"2\">address</th><th colspan=\"2\">" \
			"cnt</th>\n" \
			"  <tr>\n" \
			"  <th>L1</th><th>L2</th><th>L1</th><th>L2</th>\n" \
			"  </tr>\n", title);
	} else {
		fprintf(dt->cur_out,
			"<table summary=\"%s\" border=\"1\"><tr>\n" \
			"  <th rowspan=\"2\">base</th>\n" \
			"  <th colspan=\"2\">branch</th>\n" \
			"  <th colspan=\"2\">next</th></tr>\n" \
			"  <tr>\n" \
			"  <th>address</th><th>cnt</th>\n" \
			"  <th>address</th><th>cnt</th>\n" \
			"  </tr>\n", title);
	}
}

static struct src_info* chk_branch_point(struct cov_out_data *dt, int side,
					 struct range_to_name *r2n,
					 UINT64 addr, long cnt,
					 const char **__src, size_t *ln)
{
	char *cdir = NULL, *src, *func;
	char type;
	size_t offset;
	DWORD line;

	*__src = NULL;
	if (r2n
	    && get_source_info(&r2n->bi, addr, &cdir, &src, &func, &line, &offset)
	    		== SUCCESS
	    && src && line) {
	    *ln = line;
		*__src = src;
		type = cnt ? T_EXECUTED : T_NOT_EXECUTED;
		return chk_src_line_type(dt, side, cdir, src, *ln, type);
	}
	return NULL;
}

enum {
	BRANCH_INFO_OK,
	BRANCH_INFO_BRANCH,
	BRANCH_INFO_FALLTHROUGH,
	BRANCH_INFO_NT,
};

static int get_bi_type(struct branch_info *bi)
{
	if (bi->b_cnt && bi->f_cnt)
		return BRANCH_INFO_OK;
	else if (bi->b_cnt)
		return BRANCH_INFO_BRANCH;
	else if (bi->f_cnt)
		return BRANCH_INFO_FALLTHROUGH;
	return BRANCH_INFO_NT;
}

static inline char* get_bi_color(struct branch_info *bi)
{
	if (bi->b_cnt && bi->f_cnt)
		return COLOR_OK;
	else if (bi->b_cnt || bi->f_cnt)
		return COLOR_HT;
	return COLOR_NT;
}

static inline char *get_bi2_color(struct branch_info *bi1,
				  struct branch_info *bi2)
{
	int t1, t2;

	if (!bi2)
		return get_bi_color(bi1);
	t1 = get_bi_type(bi1);
	t2 = get_bi_type(bi2);
	if (t1 == t2) {
		switch (t1) {
		case BCOV_TYPE_OK:
			return COLOR_BOTH_OK;
		case BCOV_TYPE_HT:
			return COLOR_BOTH_HT;
		default:
			return COLOR_BOTH_NT;
		}
	} else
		return get_bi_color(bi2);
}

static bool_t is_bi2_diff(struct branch_info *bi1, struct branch_info *bi2)
{
	int t1, t2;

	if (!bi2)
		return TRUE;
	t1 = get_bi_type(bi1);
	t2 = get_bi_type(bi2);
	return (t1 != t2);
}

#define get_target_frame(dt, side) \
	(dt)->chk_type == CHK_DIFF ? \
		((side) == 0 ? "s1" : "s2") : "src"

static inline void __out_branch_html_each(FILE *out, struct cov_out_data *dt,
					  int side, struct branch_info *bi,
					  struct branch_info *bi2,
					  long *same, long *diff)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;
	const char *src;
	char *tmp, *color, *ref = "";
	size_t ln;
	struct src_info *info;

	if (same && diff) {
		if (is_bi2_diff(bi, bi2))
			(*diff)++;
		else
			(*same)++;
		return;
	}
	color = get_bi2_color(bi, bi2);
	fprintf(out, "<td bgcolor=\"%s\">", color);
	info = chk_branch_point(dt, side, r2n, bi->base, bi->b_cnt + bi->f_cnt,
				&src, &ln);
	if (info) {
		ref = get_src_html_path(dt, info, side, TRUE);
		if (dt->chk_type == CHK_SAME)
			chk_branch_point(dt, 1, r2n, bi2->base,
					 bi2->b_cnt + bi2->f_cnt, &src, &ln);
		tmp = _strdup(src);
		fprintf(out,
			"<a href=\"%s#%d\" target=\"%s\">%s,%d</a></td>\n",
			ref, ln, get_target_frame(dt, side), tmp, ln); //basename(tmp)
		free(tmp);
	} else if (src && ln) {
		tmp = _strdup(src);
		fprintf(out, "%s,%d</td>\n", tmp, ln); //basename(tmp)
		free(tmp);
	} else {
		fprintf(out, "0x%08llx</td>\n", bi->base);
	}
	if (get_jmp_a_addr(bi->branch) == UNKNOWN_BADDR)
		fprintf(out, "    <td>----------</td>");
	else {
		chk_branch_point(dt, side, bi->branch.r2n, bi->branch.addr,
				 bi->b_cnt, &src, &ln);
		if (src && ln) {
			if (dt->chk_type == CHK_SAME)
				chk_branch_point(dt, 1, bi2->branch.r2n,
						 bi2->branch.addr, bi2->b_cnt,
						 &src, &ln);
			tmp = _strdup(src);
			fprintf(out, "    <td>%s,%d</td>", tmp, ln); //basename(tmp)
			free(tmp);
		} else {
			fprintf(out, "    <td>0x%08llx</td>",
				get_jmp_a_addr(bi->branch));
		}
	}
	fprintf(out, "<td align=\"right\">%d</td>\n", bi->b_cnt);
	if (dt->chk_type == CHK_SAME)
		fprintf(out, "<td align=\"right\">%d</td>\n", bi2->b_cnt);
	if (bi->fall == UNKNOWN_BADDR)
		fprintf(out, "    <td></td><td align=\"right\"></td>");
	else {
		chk_branch_point(dt, side, r2n, bi->fall, bi->f_cnt, &src, &ln);
		if (src && ln) {
			if (dt->chk_type == CHK_SAME)
				chk_branch_point(dt, 1, r2n, bi2->fall,
						 bi2->f_cnt, &src, &ln);
			tmp = _strdup(src);
			fprintf(out, "    <td>%s,%d</td>", tmp, ln); //basename(tmp)
			free(tmp);
		} else {
			fprintf(out, "    <td>0x%08llx</td>", bi->fall);
		}
		fprintf(out, "<td align=\"right\">%d</td>", bi->f_cnt);
		if (dt->chk_type == CHK_SAME)
			fprintf(out, "<td align=\"right\">%d</td>",
				bi2->f_cnt);
	}
}

void out_branch_html_each(struct cov_out_data *dt, int side,
			  struct branch_info *bi)
{
	fprintf(dt->cur_out, "<tr>");
	__out_branch_html_each(dt->cur_out, dt, side, bi, NULL, NULL, NULL);
	fprintf(dt->cur_out, "</tr>\n");
}

void out_branch_html_each2(struct cov_out_data *dt,
			   struct branch_info *bi, struct branch_info *bi2,
			   long *same, long *diff)
{
	if (!(same || diff))
		fprintf(dt->cur_out, "<tr>");
	__out_branch_html_each(dt->cur_out, dt, 0, bi, bi2, same, diff);
	if (!(same || diff))
		fprintf(dt->cur_out, "</tr>\n");
}

void out_branch_html_end(struct cov_out_data *dt)
{
	fprintf(dt->cur_out,
		"</table>\n" \
		"</body></html>\n");
	close_html(dt);
}

void out_state_html_start(struct cov_out_data *dt, long same, long diff)
{
	char title[MAX_LINE_LEN + 1];

	open_html(dt);
	title[MAX_LINE_LEN] = '\0';
	sprintf_s(title, MAX_LINE_LEN, "%s state coverage", dt->cur_ELFname);
	out_html_normal_header(dt->cur_out, title, HEAD_TYPE_NORMAL, NULL);
	fprintf(dt->cur_out, "<body>\n");
	if (dt->chk_type == CHK_SAME) {
		out_diff_same_diff(dt, same, diff);
		fprintf(dt->cur_out,
			"<table summary=\"%s\" border=\"1\">" \
			"<tr><th rowspan=\"2\">state</th><th colspan=\"2\">" \
			"exec</th></tr>\n" \
			"<tr><th>L1</th><th>L2</th></tr>\n", title);
	} else {
		fprintf(dt->cur_out,
			"<table summary=\"%s\" border=\"1\">" \
			"<tr><th>state</th><th>exec</th></tr>\n", title);
	}
}

#define get_state_type_and_mark(is_exec, type, mark) \
	do { \
		if (is_exec) { \
			type = T_EXECUTED; \
			mark = "Y"; \
		} else { \
			type = T_NOT_EXECUTED; \
			mark = "N"; \
		} \
	} while (0)

static inline void
chk_src_line_to_state_end(struct cov_out_data *dt, int side, UINT64 base,
			  char type, char type2, const char *src,
			  const char *func, size_t ln)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;
	//int se_ln;
	char *cdir, *se_src, *se_func;
	size_t offset;
	DWORD line;

	get_source_info(&r2n->bi, base, &cdir, &se_src, &se_func, &line, &offset);
	if (line == 0)	/* can't get source information? */
		return;
	if (se_src && strcmp(src, se_src) == 0) {
		for (ln++; ln <= line; ln++) {
			chk_src_line_type(dt, side, cdir, src, ln, type);
			if (dt->chk_type == CHK_SAME)
				chk_src_line_type(dt, 1, cdir, src, ln, type2);
		}
	} else {
		/* In case of the state's top or bottom instruction is the 'C
		 * macro', we can't colorize the source range from ln to se_ln.
		 * So, we can colorize only both instruction's source line...
		 */
		chk_src_line_type(dt, side, cdir, se_src, line, type);
		if (dt->chk_type == CHK_SAME)
			chk_src_line_type(dt, 1, cdir, se_src, line, type2);
	}
}

static inline void __out_state_html_each(FILE *out, struct cov_out_data *dt,
					 int side, bool_t is_exec,
					 bool_t is_exec2, UINT64 addr,
					 UINT64 base, int uk_cnt)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;
	//int ln;
	char *cdir, *src, *func;
	struct src_info *info = NULL;
	char *color, *mark, *mark2 = "", *ref, type, type2 = T_NONE, *p;
	size_t offset;
	DWORD line;

	if (dt->chk_type == CHK_SAME) { 
		if (is_exec == is_exec2)
			color = is_exec2 ? COLOR_BOTH_OK : COLOR_BOTH_NT;
		else
			color = is_exec2 ? COLOR_OK : COLOR_NT;
		get_state_type_and_mark(is_exec2, type2, mark2);
		side = 0;
	} else {
		color = is_exec ? COLOR_OK : COLOR_NT;
	}
	get_state_type_and_mark(is_exec, type, mark);
	if (uk_cnt > 1)
		fprintf(out, "<td bgcolor=\"%s\" rowspan=\"%d\">",
			color, uk_cnt);
	else
		fprintf(out, "<td bgcolor=\"%s\">", color);
	cdir = NULL;
	get_source_info(&r2n->bi, addr, &cdir, &src, &func, &line, &offset);
	if (line && (info = chk_src_line_type(dt, side, cdir, src, line, type))) {
		ref = get_src_html_path(dt, info, side, TRUE);
		if (dt->chk_type == CHK_SAME)
			chk_src_line_type(dt, 1, cdir, src, line, type2);
		p = _strdup(src);
		fprintf(out,
			"<a href=\"%s#%d\" target=\"%s\">%s,%d</a>",
			ref, line, get_target_frame(dt, side), p, line); //basename(p)
		free(p);
	} else if (src && line) {
		p = _strdup(src);
		fprintf(out, "%s,%d", p, line); //basename(p)
		free(p);
	} else {
		fprintf(out, "0x%08llx", addr);
	}
	if (info && addr != base)
		chk_src_line_to_state_end(dt, side, base, type, type2,
					  src, func, line);

	fprintf(out, "</td>");
	if (uk_cnt > 1)
		fprintf(out, "<td align=\"center\" rowspan=\"%d\">%s</td>",
			uk_cnt, mark);
	else
		fprintf(out, "<td align=\"center\">%s</td>", mark);
	if (dt->chk_type == CHK_SAME)
		fprintf(out, "<td align=\"center\">%s</td>", mark2);
	return;
}

void out_state_html_each(struct cov_out_data *dt, int side, bool_t is_exec,
			 struct path *p)
{
	fprintf(dt->cur_out, "<tr>");
	__out_state_html_each(dt->cur_out, dt, side, is_exec, FALSE, p->addr,
			      p->base, 0);
	fprintf(dt->cur_out, "</tr>\n");
}

void out_state_html_each2(struct cov_out_data *dt, bool_t is_exec,
			  bool_t is_exec2, struct path *p)
{
	fprintf(dt->cur_out, "<tr>");
	__out_state_html_each(dt->cur_out, dt, 0, is_exec, is_exec2, p->addr,
			      p->base, 0);
	fprintf(dt->cur_out, "</tr>\n");
}

#define TREE_MARGIN_VAL		2.0
#define TREE_CTRL_CHILD_CHAR	'T'
#define TREE_CTRL_COV_CHAR	'C'

void out_func_tree_html_start(struct cov_out_data *dt,
			      char *s_inc, char *s_exc)
{
	char path[PATH_MAX + 1];
	char title[MAX_LINE_LEN + 1];
	errno_t err;

	path[PATH_MAX] = '\0';
	_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/%s", dt->outdir, TREE_HTML_PATH);
	err = fopen_s(&dt->ftree_out, path, "w");
	if (err) {
		//fprintf(stderr, "%s can't open.(%s)\n", path,
		//	strerror(errno));
		return;
	}
	title[MAX_LINE_LEN] = '\0';
	sprintf_s(title, MAX_LINE_LEN, "function tree");
	out_html_normal_header(dt->ftree_out, title, HEAD_TYPE_JS,
			       "../" JS_TREE_MENU);
	fprintf(dt->ftree_out, "<body>\n");
	fprintf(dt->ftree_out, "<b>includes: </b>%s<br>\n", s_inc);
	fprintf(dt->ftree_out, "<b>excludes: </b>%s<br>\n", s_exc);
	fprintf(dt->ftree_out,
		"<a href=\"javascript:treeMenu('cov_format')\">" \
		"View coverage table format</a>\n" \
		"<div id=\"cov_format\" style=\"display:none\">" \
		"<table summary=\"cov_format\" border=\"1\">" \
		"<tr>" \
		"<th colspan=\"2\">state coverage</th>" \
		"<th colspan=\"5\">branch coverage</th>" \
		"</tr>" \
		"<tr>" \
		"<th>state</th><th>exec</th>" \
		"<th>base</th><th>branch</th><th>cnt</th>" \
		"<th>next</th><th>cnt</th>" \
		"</tr>" \
		"</table></div><br><br>\n");
}

static inline void out_ftree_html_each_bcov(struct cov_out_data *dt, int side,
					    int bcov_type,
					    struct branch_info *bi)
{
	if (bi->uk_id)
		fprintf(dt->ftree_out, "<tr>");
	__out_branch_html_each(dt->ftree_out, dt, side, bi, NULL, NULL, NULL);
	if (bi->uk_id)
		fprintf(dt->ftree_out, "</tr>\n");
}

static void out_ftree_html_each_cov(struct cov_out_data *dt, int side,
				    char *fname, struct func_chk *fc, int nest,
				    int type)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;
	struct path *p;
	INT i;

	fprintf(dt->ftree_out,
		"<div id=\"%s_%c\" style=\"display:none\">\n" \
		"<table summary=\"%s\" border=\"1\" style=\"margin-left:" \
		" %.1fem\">\n",
		fname, TREE_CTRL_COV_CHAR, fname, TREE_MARGIN_VAL);
	i = r2n->num_path_array;
	find_path_by_addr(r2n, &i, fc->dest.addr);
	for (; i < r2n->num_path_array; i++) {
		p = r2n->path_array[i];
		if (p->addr >= fc->end)
			break;
		fprintf(dt->ftree_out, "<tr>");
		__out_state_html_each(dt->ftree_out, dt, side, p->cnt > 0,
				      FALSE, p->addr, p->base,
				      get_unknown_bcnt(p));
		if (p->type == BTYPE_BRANCH || IS_SWITCH_JMP(p))
			do_one_branch_coverage(dt, side, p,
					       out_ftree_html_each_bcov);
		else
			fprintf(dt->ftree_out,
				"<td></td><td></td><td></td><td></td><td></td>"
				);
		fprintf(dt->ftree_out, "</tr>\n");
	}
	fprintf(dt->ftree_out, "</table><br></div>");
}

void out_func_tree_html_each_enter(struct cov_out_data *dt, int side,
				   struct func_chk *fc, int nest, int type,
				   bool_t has_child)
{
	UINT64 addr = fc->dest.addr;
	char *color, buf[MAX_LINE_LEN], *p_fname, *p_ref;
	int exec_type;

	switch (type) {
	case BCOV_TYPE_OK:
		exec_type = T_EXECUTED;
		color = COLOR_OK;
		break;
	case BCOV_TYPE_NT:
		exec_type = T_NOT_EXECUTED;
		color = COLOR_NT;
		break;
	case BCOV_TYPE_HT:	/* already displayed function */
		exec_type = T_NOT_EXECUTED;
		color = COLOR_ALREADY;
		break;
	default:
		/* not reached */
		return;
	}
	if (get_fname_and_ref_str(dt, side, addr, exec_type, buf,
				  &p_fname, &p_ref) == FAILURE)
		return;

	fprintf(dt->ftree_out,
		"<div style=\"margin-left: %.1fem\"><nobr>",
		nest ? TREE_MARGIN_VAL : 0);
	if (!has_child)
		fprintf(dt->ftree_out, "%c ", TREE_CTRL_CHILD_CHAR);
	else
		fprintf(dt->ftree_out,
			"<a href=\"javascript:treeMenu('%s_%c')\">%c</a> ",
			p_fname, TREE_CTRL_CHILD_CHAR, TREE_CTRL_CHILD_CHAR);
	if (type == BCOV_TYPE_HT)
		fprintf(dt->ftree_out, "%c ", TREE_CTRL_COV_CHAR);
	else
		fprintf(dt->ftree_out,
			"<a href=\"javascript:treeMenu('%s_%c')\">%c</a> ",
			p_fname, TREE_CTRL_COV_CHAR, TREE_CTRL_COV_CHAR);
	fprintf(dt->ftree_out, "<span style=\"background:%s\">", color);
	if (p_ref)
		fprintf(dt->ftree_out, "<a href=\"%s\" target=\"src\">%s</a>",
			p_ref, p_fname);
	else
		fprintf(dt->ftree_out, "%s", p_fname);
	fprintf(dt->ftree_out, "</span> %d (F:%d)</nobr>",
		fc->cnt, fc->tree_weight);

	if (type != BCOV_TYPE_HT)
		out_ftree_html_each_cov(dt, side, p_fname, fc, nest, type);
	if (has_child)
		fprintf(dt->ftree_out,
			"<div id=\"%s_%c\" style=\"display:%s\">\n",
			p_fname, TREE_CTRL_CHILD_CHAR,
			(nest > 0 ? "none" : "block"));
}

void out_func_tree_html_each_exit(struct cov_out_data *dt, int nest,
				  bool_t has_child)
{
	if (has_child)
		fprintf(dt->ftree_out, "</div>");
	fprintf(dt->ftree_out, "</div>\n");
}

void out_func_tree_html_each_invalid(struct cov_out_data *dt, int side,
				     struct func_chk *fc)
{
	UINT64 addr = fc->dest.addr;
	char buf[MAX_LINE_LEN], *p_fname, *p_ref;

	if (get_fname_and_ref_str(dt, side, addr, T_EXECUTED, buf,
				  &p_fname, &p_ref) == FAILURE)
		return;
	fprintf(dt->ftree_out, "UT <span style=\"background:%s\">", COLOR_OK);
	if (p_ref)
		fprintf(dt->ftree_out, "<a href=\"%s\" target=\"src\">%s</a>",
			p_ref, p_fname);
	else
		fprintf(dt->ftree_out, "%s", p_fname);
	fprintf(dt->ftree_out, "</span> %d</nobr><br>",
		fc->cnt);
}

void out_func_tree_html_end(struct cov_out_data *dt)
{
	fprintf(dt->ftree_out,
		"</body></html>\n");
	fclose(dt->ftree_out);
}

void out_func_html_start(struct cov_out_data *dt, long same, long diff)
{
	char title[MAX_LINE_LEN + 1], *js_path;
	int head_type;

	open_html(dt);
	title[MAX_LINE_LEN] = '\0';
	sprintf_s(title, MAX_LINE_LEN, "%s function coverage", dt->cur_ELFname);
	if (dt->chk_type == CHK_DIFF) {
		head_type = HEAD_TYPE_JS;
		js_path = "../" JS_BOTH_OPEN;
	} else {
		head_type = HEAD_TYPE_NORMAL;
		js_path = NULL;
	}
	out_html_normal_header(dt->cur_out, title, head_type, js_path);
	if (dt->chk_type == CHK_DIFF)
		fprintf(dt->cur_out,
			"<body onKeyPress=\"syncScroll(event)\">\n" \
			"Press 'u', 'd' key for sync-scroll both sources.<br>" \
			"\n");
	else
		fprintf(dt->cur_out, "<body>\n");
	if (dt->chk_type == CHK_SINGLE) {
		fprintf(dt->cur_out,
			"<table summary=\"%s\" border=\"1\">" \
			"<tr><th>function</th><th>count</th>%s</tr>\n",
			title, dt->limit_by_funcs ? "<th>n-function</th>" : "");
	} else {
		if (dt->chk_type == CHK_SAME)
			out_diff_same_diff(dt, same, diff);
		fprintf(dt->cur_out,
			"<table summary=\"%s\" border=\"1\">" \
			"<tr><th rowspan=\"2\">function</th><th colspan=\"2\">"\
			"count</th></tr>\n" \
			"<tr><th>L1</th><th>L2</th></tr>\n", title);
	}
}

static char* get_src_html_path(struct cov_out_data *dt, struct src_info *info,
			       int side, bool_t is_ref)
{
	int rc;
	char *diff_sep;

	if (info->html_out_path[0] != '\0' && info->is_ref == is_ref)
		return info->html_out_path;

	// There might be same CU in the two traced logs. If we check the
	// different ELFs log, we don't want to overwrite same CU's source html.
	// So, we create two source htmls in different directories.
	diff_sep = dt->chk_type == CHK_DIFF ? (side == 0 ? "1/" : "2/") : "";

	if (is_ref)
		rc = _snprintf_s(info->html_out_path, PATH_MAX, PATH_MAX - 1,
			      "../src/%s%s.html", diff_sep, info->srcpath + 3);
	else
		rc = _snprintf_s(info->html_out_path, PATH_MAX, PATH_MAX - 1,
			      "%s/src/%s%s.html", dt->outdir, diff_sep,
			      info->srcpath + 3);
	if (rc > PATH_MAX)
		printf("WARN: PATH_MAX is too short.\n");
	info->is_ref = is_ref;
	return info->html_out_path;
}

static struct src_info* chk_src_line_type(struct cov_out_data *dt, int side,
					  const char *cdir, const char *src,
					  size_t ln, char type)
{
	struct r2i_pack *r2p = dt->r2p[side];
	FILE *f = NULL;
	char path[PATH_MAX + 1], *dir;
	struct src_info *info = NULL;
	INT i;
	char buf[MAX_LINE_LEN + 1];
	char *pCh;
	errno_t err;

	if (!ln)
		return NULL;

	/* get absolute path */
	//if (src[0] == '/')
	if (!r2p->srcdir)
		sprintf_s(path, PATH_MAX, "%s%s", get_elf_path_prefix(), src);
	else {
		//if (!cdir && !r2p->srcdir)
		//	return NULL;
		//dir =  cdir ? (char*)cdir : r2p->srcdir;
		dir =  r2p->srcdir;
		pCh = strchr(src, '\\');
		if (pCh) pCh = strchr(pCh + 1, '\\');
		pCh = pCh ? pCh:src;
		sprintf_s(path, PATH_MAX, "%s%s%s",
			get_elf_path_prefix(), dir, pCh);
	}

	/* search into src_info structures */
	for (i = r2p->src_info_num - 1; i >= 0; i--) {
		info = r2p->src_info[i];
		if (strcmp(info->path, path) == 0) {
			if ((INT)ln > info->ln_max)
				return NULL;
			goto CHK_LINE_TYPE;
		}
	}
	/* check source file existance and max line number */
	err = fopen_s(&f, path, "r");
	if (err)
		return NULL;
	for (i = 0; fgets(buf, MAX_LINE_LEN, f); i++);
	fclose(f);
	if ((INT)ln > i)
		return NULL;

	info = calloc(1, sizeof(*info));
	strcpy_s(info->path, PATH_MAX, path);
	strcpy_s(info->srcpath, PATH_MAX, src);
	info->ln_max = i;
	info->exec_types = calloc(i, sizeof(*info->exec_types));
	r2p->src_info = realloc(r2p->src_info,
				 (r2p->src_info_num + 1) *
					sizeof(*r2p->src_info));
	r2p->src_info[r2p->src_info_num++] = info;
CHK_LINE_TYPE:
	if (info->exec_types[ln - 1] == T_NONE ||
	    (info->exec_types[ln - 1] != type && type == T_EXECUTED))
		info->exec_types[ln - 1] = type;
	return info;
}

static char escape_need_chars[] = "\t<>&\"";
static char *escape_htmls[] = {
	"        ",
	"&lt;",
	"&gt;",
	"&amp;",
	"&quot;",
};

static void escape_for_html(char *buf)
{
	INT len_max = (INT)strlen(buf), len, n;
	char *from, *to, *p, tmp[MAX_LINE_LEN + 1];

	tmp[MAX_LINE_LEN] = '\0';
	len = 0;
	for (from = buf, to = tmp; from - buf < len_max;) {
		p = strchr(escape_need_chars, *from);
		if (p) {
			from++;
			p = escape_htmls[p - escape_need_chars];
			n = (INT)strlen(p);
			if (len + n > MAX_LINE_LEN) {
				n = MAX_LINE_LEN - (len + n);
				_snprintf_s(to, MAX_LINE_LEN - len, MAX_LINE_LEN - len, "%s", p);
			} else
				sprintf_s(to, MAX_LINE_LEN - len, "%s", p);
			to += n;
			len += n;
		} else {
			*to++ = *from++;
			len++;
		}
	}
	*to = '\0';
	strcpy_s(buf, MAX_LINE_LEN, tmp);
}

static int get_ln_cols(struct src_info *info)
{
	int cols = 0;
	long left;

	for (left = info->ln_max + 1; left; left = left / 10)
		cols++;
	return cols;
}

static inline char *__type2color(char type)
{
	//return COLOR_WT;
	switch (type) {
	case T_NOT_EXECUTED:
		return COLOR_NT;
	case T_EXECUTED:
		return COLOR_OK;
	case T_UNKNOWN:
		return COLOR_HT;
	default:
		return "";
	}
}

static char* type2color(int chk_type, char type, char type2)
{
	if (chk_type == CHK_SAME) {
		if (type == type2) {
			switch (type2) {
			case T_NOT_EXECUTED:
				return COLOR_BOTH_NT;
			case T_EXECUTED:
				return COLOR_BOTH_OK;
			case T_UNKNOWN:
				return COLOR_BOTH_HT;
			default:
				return "";
			}
		} else
			return __type2color(type2);
	} else
		return __type2color(type);
}

#define CHK_EXEC_TYPE(info, ln, type) \
	do { \
		if ((info)->exec_types[(ln)] != T_NONE) \
			type = (info)->exec_types[(ln)]; \
		else if (type != T_NONE) \
			type = T_UNKNOWN; \
	} while (0)

static void out_src_html(struct cov_out_data *dt, int side)
{
	struct r2i_pack *r2p = dt->r2p[side], *r2p2 = NULL;
	long i, j, ln;
	struct src_info *info = NULL, *info2 = NULL;
	int ln_cols;
	FILE *r, *w;
	char type, type2, *p, *path, *color, buf[MAX_LINE_LEN + 1];
	errno_t err;

	if (dt->chk_type == CHK_SAME)
		r2p2 = dt->r2p[1];
	buf[MAX_LINE_LEN] = '\0';
	for (i = 0; i < r2p->src_info_num; i++) {
		info = r2p->src_info[i];
		if (dt->chk_type == CHK_SAME) {
			for (j = 0; j < r2p2->src_info_num; j++) {
				info2 = r2p2->src_info[j];
				if (strcmp(info->path, info2->path) == 0)
					break;
			}
			if (j == r2p2->src_info_num) {
				//fprintf(stderr, "Source file (%s) not found.\n",
				//	info->path);
				continue;
			}
		}
		_snprintf_s(buf, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s", info->path);
		err = fopen_s(&r, buf, "r");
		if (err) {
			//fprintf(stdout, "%s can't open.(%s)\n",
			//	buf, strerror(errno));
			break;
		}
		path = get_src_html_path(dt, info, side, FALSE);
		p = _strdup(path);
		if (dir_chk_and_create(p, FALSE) == FAILURE) { //dirname(p)
			free(p);
			fclose(r);
			break;
		}
		free(p);
		err = fopen_s(&w, path, "w");
		if (err) {
			//fprintf(stdout, "%s can't open.(%s)\n",
			//	path, strerror(errno));
			break;
		}
		ln_cols = get_ln_cols(info);
		out_html_normal_header(w, "src", HEAD_TYPE_SRC, NULL);
		fprintf(w, "<body onload=\"resetall()\" style=\"font-size:8pt\"><pre>\n"); //onload=\"resetall()\"
		type = type2 = T_NONE;
		for (ln = 0; fgets(buf, MAX_LINE_LEN, r); ln++) {
			CHK_EXEC_TYPE(info, ln, type);
			if (dt->chk_type == CHK_SAME) {
				CHK_EXEC_TYPE(info2, ln, type2);
			}
			fprintf(w, "%*ld: ", ln_cols, ln + 1);
			buf[strlen(buf) - 1] = '\0';
			escape_for_html(buf);
			color = type2color(dt->chk_type, type, type2);
			if (color[0] == '\0')
				fprintf(w, "%s\n", buf);
			else
				fprintf(w, "<a name=\"%ld\"" \
					" style=\"background:%s\">%s</a>\n",
					ln + 1, color, buf);
				//fprintf(w, "<a name=\"%ld\"" \
				//	">%s</a>\n",
				//	ln + 1, buf);
			/* '}' of a line-head is regarded as the end of a
			 * function.
			 */
			if (buf[0] == '}')
				type = type2 = T_NONE;
		}
		fprintf(w, "</pre></body></html>\n");
		fclose(r);
		fclose(w);
	}
}

/*-----------------------------------------------------------------------------
 *  initialize
 *-----------------------------------------------------------------------------
 */
void CreateDir(char* Path)
{
	char DirName[PATH_MAX];
	char* p = Path;
	char* q = DirName;	

	while(*p)
	{
		if (('\\' == *p) || ('/' == *p))
		{
			if (':' != *(p-1))
			{
				_mkdir(DirName);
			}
		}
		*q++ = *p++;
		*q = '\0';
	}
	_mkdir(DirName);
}

int dir_chk_and_create(char *path, bool_t err_on_exists)
{
	struct stat st;
	char cmd[MAX_LINE_LEN + 1], folder[MAX_LINE_LEN + 1];
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char ext[_MAX_EXT];

	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			cmd[MAX_LINE_LEN] = '\0';
			//_snprintf(buf, MAX_LINE_LEN, "mkdir -p \"%s\"", path);
			_splitpath_s(path, drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, ext, _MAX_EXT);
			if (ext[0])
			{
				_snprintf_s(folder, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s%s", drive, dir);
				//_snprintf(cmd, MAX_LINE_LEN, "mkdir \"%s%s\"", drive, dir);
				_snprintf_s(cmd, MAX_LINE_LEN, MAX_LINE_LEN - 1, "\"%s%s\"", drive, dir);
			}
			else
			{
				_snprintf_s(folder, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s", path);
				//_snprintf(cmd, MAX_LINE_LEN, "mkdir \"%s\"", path);
				_snprintf_s(cmd, MAX_LINE_LEN, MAX_LINE_LEN - 1, "\"%s\"", path);
			}
			if (stat(folder, &st) < 0) {
				//_snprintf(buf, MAX_LINE_LEN, "mkdir \"%s%s\"", drive, dir);
				CreateDir(folder);
				//if (system(cmd) < 0) {
				//	fprintf(stderr, "%s can't create.\n", dir);
				//	return FAILURE;
				//}
			}
			return SUCCESS;
		}
		//fprintf(stderr, "%s can't get stat.(%s)\n",
		//	dir, strerror(errno));
		return FAILURE;
	}
	if (err_on_exists) {
		//fprintf(stderr, "%s already exists.\n", path);
		return FAILURE;
	}
	//if (!S_ISDIR(st.st_mode)) {
	//	fprintf(stderr, "%s is not directory.\n", path);
	//	return FAILURE;
	//}
	return SUCCESS;
}

int init_html_output(struct cov_out_data *dt)
{
	char path[PATH_MAX + 1];
	errno_t err;

	path[PATH_MAX] = '\0';
	_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/each", dt->outdir);
	if (dir_chk_and_create(path, FALSE) == FAILURE) // TRUE
		return FAILURE;

	path[PATH_MAX] = '\0';
	_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/summary.html", dt->outdir);
	err = fopen_s(&dt->summary_out, path, "w");
	if (err) {
		//fprintf(stderr, "%s can't open.(%s)\n", path,
		//	strerror(errno));
		return FAILURE;
	}
	if (out_top_html(dt) == FAILURE)
		return FAILURE;
	if (out_title_html(dt) == FAILURE)
		return FAILURE;
	if (dt->chk_type == CHK_DIFF) {
		path[PATH_MAX] = '\0';
		_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/src", dt->outdir);
		if (dir_chk_and_create(path, TRUE) == FAILURE)
			return FAILURE;
		out_both_open_and_scrl_js(dt);
		out_blank_html(dt);	// for ELF1
		out_blank_html(dt);	// for ELF2
	} else if (dt->chk_type == CHK_SINGLE && dt->limit_by_funcs)
		out_tree_menu_js(dt);
	out_summary_html_start(dt);
	return SUCCESS;
}

int exit_html_output(struct cov_out_data *dt, int limit_by_funcs)
{
	out_src_html(dt, 0);
	if (dt->chk_type == CHK_DIFF)
		out_src_html(dt, 1);
	out_summary_html_end(dt, limit_by_funcs);
	if (dt->summary_out)
		fclose(dt->summary_out);
	return SUCCESS;
}

int init_html2_output(struct cov_out_data *dt)
{
	if (out_top2_html(dt) == FAILURE)
		return FAILURE;
	//if (out_title2_html(dt) == FAILURE)
	//	return FAILURE;
	
	return SUCCESS;
}

void out_execpath_html_start(FILE *f)
{
	out_html_normal_header(f, "Execution Paths", HEAD_TYPE_JQUERY, "dist/libs/jquery.js");
#ifdef _OUT_TABLE
	fprintf(f,
		"<body>\n" \
		"<table class=\"paths\">\n" \
		"<colgroup><col style=\"width:140px;\">\n" \
		"<col style=\"width:320px;\"></colgroup>\n" \
		"<tr><th>driver</th>" \
		"<th>function/address/line</th></tr>\n");
#else
	fprintf(f,
		"<body>\n" \
		"<div id=\"pathstree\"><ul>\n");
#endif
}

void out_execpath_html_end(FILE *f)
{
#ifdef _OUT_TABLE
	fprintf(f, "</table></body></html>\n");
#else
	fprintf(f, "</ul></div></body></html>\n");
#endif
}

