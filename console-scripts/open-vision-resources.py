import csv

from java.awt import Container
from javax.swing import JFileChooser, JOptionPane
from javax.swing.filechooser import FileNameExtensionFilter

from com.inductiveautomation.ignition.designer import IgnitionDesigner
from com.inductiveautomation.factorypmi.designer.workspace import WindowWorkspace


# ============================================================
# CONFIG
# ============================================================

BATCH_SIZE = 50
OPEN_DELAY_MS = 500


# ============================================================
# DESIGNER HELPERS
# ============================================================

def findWindowWorkspace(component):
    if isinstance(component, WindowWorkspace):
        return component

    if isinstance(component, Container):
        for child in component.getComponents():
            result = findWindowWorkspace(child)

            if result is not None:
                return result

    return None


def chooseCsvFile(parent):
    chooser = JFileChooser()

    chooser.setDialogTitle(
        "Select Scan83 untracked Vision binaries CSV"
    )

    chooser.setFileFilter(
        FileNameExtensionFilter(
            "CSV Files (*.csv)",
            ["csv"]
        )
    )

    result = chooser.showOpenDialog(parent)

    if result != JFileChooser.APPROVE_OPTION:
        return None

    return chooser.getSelectedFile().getAbsolutePath()


# ============================================================
# CSV HELPERS
# ============================================================

def findColumn(fieldnames, wantedName):
    if fieldnames is None:
        return None

    for field in fieldnames:
        if field.strip().lower() == wantedName.lower():
            return field

    return None


def loadResources(csvPath, projectName):

    resources = []

    f = open(csvPath, "rb")

    try:
        reader = csv.DictReader(f)

        projectColumn = findColumn(
            reader.fieldnames,
            "Project"
        )

        resourceColumn = findColumn(
            reader.fieldnames,
            "Resource"
        )

        if projectColumn is None:
            raise Exception(
                'Could not find a "Project" column in the CSV.'
            )

        if resourceColumn is None:
            raise Exception(
                'Could not find a "Resource" column in the CSV.'
            )

        for row in reader:

            rowProject = row.get(
                projectColumn,
                ""
            ).strip()

            resource = row.get(
                resourceColumn,
                ""
            ).strip()

            if rowProject.lower() != projectName.lower():
                continue

            if not resource:
                continue

            resource = resource.replace(
                "\\",
                "/"
            )

            if resource not in resources:
                resources.append(resource)

    finally:
        f.close()

    return resources


# ============================================================
# RESOURCE OPENER
# ============================================================

def openResources(resources, workspace, index=0):

    total = len(resources)

    # --------------------------------------------------------
    # FINISHED
    # --------------------------------------------------------

    if index >= total:

        JOptionPane.showMessageDialog(
            IgnitionDesigner.getFrame(),
            (
                "Finished opening %d Vision resources.\n\n"
                "Commit/close the resources and save the project."
            ) % total,
            "Scan83",
            JOptionPane.INFORMATION_MESSAGE
        )

        print ""
        print "========================================"
        print "Finished"
        print "========================================"
        print "Processed: %d" % total

        return


    # --------------------------------------------------------
    # OPEN CURRENT RESOURCE
    # --------------------------------------------------------

    resource = resources[index]
    lower = resource.lower()

    try:

        if lower.startswith("templates/"):

            path = resource[len("templates/"):]

            workspace.openTemplate(path)

            print "[%d/%d] OK   Template: %s" % (
                index + 1,
                total,
                path
            )

        elif lower.startswith("windows/"):

            path = resource[len("windows/"):]

            system.vision.openWindow(path)

            print "[%d/%d] OK   Window:   %s" % (
                index + 1,
                total,
                path
            )

        else:

            print "[%d/%d] SKIP Unknown resource type: %s" % (
                index + 1,
                total,
                resource
            )

    except Exception, e:

        print "[%d/%d] FAIL %s" % (
            index + 1,
            total,
            resource
        )

        print "             %s" % e


    nextIndex = index + 1


    # --------------------------------------------------------
    # BATCH COMPLETE
    # --------------------------------------------------------

    if (
        nextIndex < total
        and nextIndex % BATCH_SIZE == 0
    ):

        message = (
            "Opened %d of %d Vision resources.\n\n"
            "This batch is complete.\n\n"
            "Continue with the next batch?"
        ) % (
            nextIndex,
            total
        )

        result = JOptionPane.showConfirmDialog(
            IgnitionDesigner.getFrame(),
            message,
            "Scan83 - Batch Complete",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE
        )

        if result != JOptionPane.YES_OPTION:

            print ""
            print "========================================"
            print "Stopped after batch"
            print "========================================"
            print "Processed: %d of %d" % (
                nextIndex,
                total
            )

            return


    # --------------------------------------------------------
    # QUEUE NEXT RESOURCE
    # --------------------------------------------------------

    def nextResource():
        openResources(
            resources,
            workspace,
            nextIndex
        )

    system.util.invokeLater(
        nextResource,
        OPEN_DELAY_MS
    )


# ============================================================
# MAIN
# ============================================================

frame = IgnitionDesigner.getFrame()
context = frame.getContext()

projectName = context.getProjectName()

print "Current Designer project:", projectName


workspace = findWindowWorkspace(frame)

if workspace is None:

    JOptionPane.showMessageDialog(
        frame,
        "Could not locate the Vision WindowWorkspace.",
        "Scan83 Error",
        JOptionPane.ERROR_MESSAGE
    )

    raise Exception(
        "Could not locate Vision WindowWorkspace"
    )


# ------------------------------------------------------------
# SELECT SCAN83 EXPORT
# ------------------------------------------------------------

csvPath = chooseCsvFile(frame)

if csvPath is None:

    print "Cancelled."

else:

    try:

        resources = loadResources(
            csvPath,
            projectName
        )

    except Exception, e:

        JOptionPane.showMessageDialog(
            frame,
            str(e),
            "Scan83 CSV Error",
            JOptionPane.ERROR_MESSAGE
        )

        raise


    print ""
    print "Scan83 export:", csvPath
    print "Project:", projectName
    print "Matching resources:", len(resources)
    print "Batch size:", BATCH_SIZE
    print "Open delay:", OPEN_DELAY_MS, "ms"


    # --------------------------------------------------------
    # NOTHING TO DO
    # --------------------------------------------------------

    if len(resources) == 0:

        JOptionPane.showMessageDialog(
            frame,
            (
                'No untracked Vision binaries were found '
                'for project "%s".'
            ) % projectName,
            "Scan83",
            JOptionPane.INFORMATION_MESSAGE
        )


    # --------------------------------------------------------
    # CONFIRM START
    # --------------------------------------------------------

    else:

        message = (
            '%d Vision resources for project "%s" '
            'will be opened in the Designer.\n\n'
            'Batch size: %d\n'
            'Open delay: %d ms\n\n'
            'Ready to start?'
        ) % (
            len(resources),
            projectName,
            BATCH_SIZE,
            OPEN_DELAY_MS
        )

        result = JOptionPane.showConfirmDialog(
            frame,
            message,
            "Scan83 Vision Resource Opener",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.QUESTION_MESSAGE
        )


        if result == JOptionPane.YES_OPTION:

            print ""
            print "========================================"
            print "Opening %d resources..." % len(resources)
            print "========================================"
            print ""

            system.util.invokeLater(
                lambda: openResources(
                    resources,
                    workspace
                )
            )

        else:

            print "Cancelled."