"""
Script designed to perform packet inter-arrival times analysis in SRT.
"""
import math
import pathlib

from bokeh.io import output_file
import bokeh.layouts as layouts
import bokeh.models as models
import bokeh.plotting as plotting
import click
import numpy as np
import pandas as pd

import tcpdump_processing.convert as convert
import tcpdump_processing.extract_packets as extract_packets


TOOLS = 'pan,xwheel_pan,box_zoom,reset,save'


def perform_slicing(s: pd.Series):
    """
    Perform slicing of the packet IAT series `s` into following bins:
    '0 - 10',
    '10 - 100',
    '100 - 500',
    '500 - 1,000',
    '1,000 - 5,000',
    '5,000 - 10,000',
    '10,000 - 50,000',
    '50,000 - 100,000',
    '100,000 - 500,000',
    where each diapason is specified in microseconds (us).

    Attributes:
        s: `
            pd.Series` of packet inter-arrival time in microseconds (us).

    Returns:
        `bokeh` bar chart figure and table with data.
    """
    bins = [0, 10, 100, 500, 1000, 5000, 10000, 50000, 100000, 500000]
    hist, edges = np.histogram(s, bins=bins)

    bins_str = [
        '0 - 10',
        '10 - 100',
        '100 - 500',
        '500 - 1,000',
        '1,000 - 5,000',
        '5,000 - 10,000',
        '10,000 - 50,000',
        '50,000 - 100,000',
        '100,000 - 500,000'
    ]

    d = {}
    d['edges.us'] = bins_str
    d['packets'] = hist

    df = pd.DataFrame(d)
    n = df['packets'].sum()
    df['packets_cumsum'] = df['packets'].cumsum()
    df['percentage'] = df['packets'] * 100 / n
    df['percentage_cumsum'] = round(df['percentage'].cumsum(), 4)
    df['percentage'] = round(df['percentage'], 4)

    # Figure
    fig = plotting.figure(
        plot_height=300,
        plot_width=1000,
        x_range=bins_str,
        tools=TOOLS
    )
    fig.title.text = 'Inter-arrival packet time diapason vs Packets'
    fig.xaxis.axis_label = 'IAT, us'
    fig.yaxis.axis_label = 'Packets'
    fig.yaxis.formatter = models.NumeralTickFormatter(format='0,0')
    # fig.xaxis.major_label_orientation = math.pi/4
    fig.vbar(x=bins_str, top=hist, width=0.9)

    # Table
    source = models.ColumnDataSource(df)
    columns = [
        models.widgets.TableColumn(field='edges.us', title='IAT, us'),
        models.widgets.TableColumn(field='packets', title='Packets', formatter=models.NumberFormatter(format='0,0')),
        models.widgets.TableColumn(field='packets_cumsum', title='Packets cumsum', formatter=models.NumberFormatter(format='0,0')),
        models.widgets.TableColumn(field='percentage', title='Packets, %'),
        models.widgets.TableColumn(field='percentage_cumsum', title='Packets cumsum, %'),
    ]
    table = models.widgets.DataTable(columns=columns, source=source)

    return fig, table


def figure_histogram(hist, edges, title: str, normalized=False, x_range=(0, 5000)):
    """ Create and return `bokeh` histogram figure. """
    fig = plotting.figure(
        plot_height = 400,
        plot_width=800, 
        tools=TOOLS, 
        background_fill_color='#fafafa', 
        x_range=x_range
    )

    fig.quad(
        top=hist,
        bottom=0,
        left=edges[:-1],
        right=edges[1:],
        fill_color='navy',
        line_color='white',
        alpha=0.5
    )
    
    fig.title.text = title
    fig.xaxis.axis_label = 'x, us'
    fig.y_range.start = 0
    fig.grid.grid_line_color='white'

    if normalized:
        fig.yaxis.axis_label = 'f(x)'
    else:
        fig.yaxis.axis_label = 'f(x), packets'
        fig.yaxis.formatter = models.NumeralTickFormatter(format='0,0')

    return fig


def ecdf(s: pd.Series):
    """
    Calculate Empirical Cumulative Distribution Function (ECDF)
    of sample `s`.
    """
    n = len(s)
    x = np.sort(s)
    ecdf = np.arange(1, n+1) / n

    return x, ecdf


def figure_ecdf(x, ecdf, x_range=(0, 5000)):
    """ Create and return `bokeh` ECDF figure. """
    fig = plotting.figure(
        plot_height = 400,
        plot_width=800, 
        tools=TOOLS, 
        background_fill_color='#fafafa', 
        x_range=x_range
    )

    fig.title.text = 'Empirical cumulative distribution function (ECDF)'
    fig.xaxis.axis_label = 'x, us'
    fig.yaxis.axis_label = 'F(x)'

    fig.line(x, ecdf, line_color="orange", line_width=2, alpha=0.7)
    
    return fig


def get_stats(s: pd.Series):
    """ Calculate basic sample `s` statistics. """
    q1 = s.quantile(0.25)
    median = s.median()
    q3 = s.quantile(0.75)
    p90 = s.quantile(0.90)
    p95 = s.quantile(0.95)
    p99 = s.quantile(0.99)
    iqr = q3 - q1
    mean = round(s.mean(), 2)
    std = round(s.std(), 2)
    min = s.min()
    max = s.max()
    n = len(s)
    return [q1, median, q3, p90, p95, p99, iqr, mean, std, min, max, n]


def get_iqr(s: pd.Series):
    """ Calculate interquartile range (IQR) of the `s` sample. """
    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    iqr = q3 - q1
    return q1, q3, iqr


def get_fences(s: pd.Series, multiplier: float):
    """
    Calculate lower and upper fences of the `s` sample 
    for the following outliers detection.
    """
    q1, q3, iqr = get_iqr(s)
    lower = q1 - multiplier * iqr
    # Limit the lower fence by 0, because packet IAT should be >= 0
    lower = lower if lower > 0 else 0
    upper = q3 + multiplier * iqr
    return lower, upper


def remove_outliers(data: pd.DataFrame, column: str, multiplier: float):
    """ 
    Remove outliers which do not fall into the interval between
    the lower and upper fence 

    [Q1 - multiplier * IQR, Q3 + multiplier * IQR], where

    Q1 - first quartile (25th percentile),
    Q3 - third quartile (75th percentile),
    IQR - interquartile range, the difference between Q3 and Q1,
    of the sample `data[column]`.

    Multiplier is usually chosen as 1.5 or 3.

    Attributes:
        data:
            `pd.DataFrame` data frame from which the outliers should be
            removed, 
        column:
            `str` name of the column to which the above rule 
            should be applied.
        multiplier:
            Multiplier value.

    Returns:
        data_no_outliers:
            `pd.DataFrame` with outliers removed,
        outliers:
            `pd.DataFrame` with the outliers only. 
    """
    lower, upper = get_fences(data[column], multiplier)
    data_no_outliers = data[(data[column] >= lower) & (data[column] <= upper)]
    outliers = data[(data[column] < lower) | (data[column] > upper)]
    return data_no_outliers, outliers


def remove_outliers_by_quantile(data: pd.DataFrame, column: str, quant: float):
    """ 
    Remove outliers which do not fall into the interval [0, upper fence],
    where upper fence is chosen as `quant` quantile.

    There is no comparison with the lower fence = 0 done here, because
    packet IAT is by default >= 0.

    Attributes:
        data:
            `pd.DataFrame` data frame from which the outliers should be
            removed, 
        column:
            `str` name of the column to which the above rule 
            should be applied.
        quant:
            Quantile level.

    Returns:
        data_no_outliers:
            `pd.DataFrame` with outliers removed,
        outliers:
            `pd.DataFrame` with the outliers only. 
    """
    upper = data[column].quantile(quant)
    data_no_outliers = data[data[column] <= upper]
    outliers = data[data[column] > upper]
    return data_no_outliers, outliers


def panel_eda(data: pd.DataFrame):
    """
    The main panel with exploratory data analysis consisting of:
    - packet timestamp vs packet inter-arrival time plot,
    - basic statistics table,
    - bar chart and table with sliced into intervals packet inter-arrival times,
    - histograms regular and normalized, 100us bins,
    - histograms regular and normalized, 10us bins,
    - ECDF.

    Attributes:
        data:
            `pd.DataFrame` with packet inter-arrival times data preliminary
            cleaned up and consisting of the two columns `ws.time` and `ws.iat.us`,
            where `ws.time` is the packet timestamp in seconds and `ws.iat.us` is
            the corresponding inter-arrival time from the previous data packet
            in microseconds.

    Returns:
        `models.widgets.Panel` bokeh panel.
    """
    # Figure: Packet timestamp vs Inter-arrival packet time
    source_data = models.ColumnDataSource(data)

    fig_iat = plotting.figure(
        plot_height=400,
        plot_width=1000,
        x_range=(0, 10),
        tools=TOOLS
    )
    fig_iat.title.text = 'Inter-arrival packet time'
    fig_iat.xaxis.axis_label = 'Time, s'
    fig_iat.yaxis.axis_label = 'IAT, us'
    fig_iat.yaxis.formatter = models.NumeralTickFormatter(format='0,0')
    fig_iat.line(x='ws.time', y='ws.iat.us', source=source_data)

    # Table: Statistics
    stats = {}
    stats['stats'] = [
        '25th percentile (Q1), us',
        '50th percentile (Median, Q2), us',
        '75th percentile (Q3), us',
        '90th percentile, us',
        '95th percentile, us',
        '99th percentile, us',
        'Interquartile range (IQR, Q3 - Q1), us',
        'Mean, us',
        'Standard deviation, us',
        'Min, us',
        'Max, us',
        'Packets',
    ]
    stats['value'] = get_stats(data['ws.iat.us'])
    
    source_stats = models.ColumnDataSource(pd.DataFrame(stats))
    columns = [
        models.widgets.TableColumn(field='stats', title='Statistic'),
        models.widgets.TableColumn(field='value', title='Value'),
    ]
    table_stats = models.widgets.DataTable(columns=columns, source=source_stats)

    # Bar chart, table: Sliced into intervals inter-arrival packet times
    fig_slicing, table_slicing = perform_slicing(data['ws.iat.us'])

    # Histograms regular and normalized, 100us bins
    bins_100 = [n * 100 for n in range(0, 5001)]
    hist_100, edges_100 = np.histogram(data['ws.iat.us'], bins=bins_100)
    fig_hist_100 = figure_histogram(hist_100, edges_100, 'Histogram of inter-arrival packet time, 100us bins')
    hist_norm_100, edges_norm_100 = np.histogram(data['ws.iat.us'], bins=bins_100, density=True)
    fig_hist_norm_100 = figure_histogram(hist_norm_100, edges_norm_100, 'Normalized histogram of inter-arrival packet time, 100us bins', True)

    # Histograms regular and normalized, 100us bins
    bins_10 = [n * 10 for n in range(0, 50001)]
    hist_10, edges_10 = np.histogram(data['ws.iat.us'], bins=bins_10)
    fig_hist_10 = figure_histogram(hist_10, edges_10, 'Histogram of inter-arrival packet time, 10us bins')
    hist_norm_10, edges_norm_10 = np.histogram(data['ws.iat.us'], bins=bins_10, density=True)
    fig_hist_norm_10 = figure_histogram(hist_norm_10, edges_norm_10, 'Normalized histogram of inter-arrival packet time, 10us bins', True)

    # Synchronize x axeses of the histograms
    fig_hist_100.x_range = \
        fig_hist_norm_100.x_range = \
        fig_hist_10.x_range = \
        fig_hist_norm_10.x_range

    # ECDF
    x, y = ecdf(data['ws.iat.us'])
    fig_ecdf = figure_ecdf(x, y)

    # Create grid
    grid = layouts.gridplot(
        [
            [fig_iat, table_stats],
            [fig_slicing, table_slicing],
            [fig_hist_100, fig_hist_norm_100],
            [fig_hist_10, fig_hist_norm_10],
            [None, fig_ecdf],
        ]
    )

    # Create panel
    panel = models.widgets.Panel(child=grid, title='Exploratory Data Analysis')
    return panel


# TODO: Implement
""" def panel_scatter_plot(data: pd.DataFrame):
    # Horizontal bar chart
    # fig = plotting.figure(
    #     plot_height=300,
    #     plot_width=600,
    #     y_range=bins_str,
    #     tools=TOOLS
    # )
    # fig.title.text = 'Inter-arrival packet time diapason vs Packets'
    # fig.yaxis.axis_label = 'IAT, us'
    # fig.xaxis.axis_label = 'Packets'
    # fig.xaxis.formatter = models.NumeralTickFormatter(format='0,0')
    # fig.hbar(y=bins_str, right=hist, height=0.9)

    multiplier = 10
    lower, upper = get_fences(data['ws.iat.us'], multiplier)

    # data['is.outlier'] = data['ws.iat.us'].apply((data['ws.iat.us'] >= lower) & (data['ws.iat.us'] <= upper))
    # print(data)

    data_no_outliers = data[(data['ws.iat.us'] >= lower) & (data['ws.iat.us'] <= upper)]
    outliers = data[(data['ws.iat.us'] < lower) | (data['ws.iat.us'] > upper)]

    data_no_outliers = data_no_outliers[data_no_outliers['ws.time'] < 10]
    outliers = outliers[outliers['ws.time'] < 10]

    source_data_no_outliers = models.ColumnDataSource(data_no_outliers)
    source_outliers = models.ColumnDataSource(outliers)

    fig_scatter = plotting.figure(
        plot_height=400,
        plot_width=1000,
        x_range=(0, 10),
        tools=TOOLS
    )
    fig_scatter.title.text = 'Inter-arrival packet time'
    fig_scatter.xaxis.axis_label = 'Time, s'
    fig_scatter.yaxis.axis_label = 'IAT, us'
    fig_scatter.yaxis.formatter = models.NumeralTickFormatter(format='0,0')
    # fig_iat.line(x='ws.time', y='ws.iat.us', source=source_data)
    fig_scatter.scatter(x='ws.time', y='ws.iat.us', line_color=None, fill_alpha=0.3, size=5, source=source_data_no_outliers, legend='data')
    fig_scatter.scatter(x='ws.time', y='ws.iat.us', line_color=None, fill_alpha=0.3, size=5, color='red', source=source_outliers, legend='outliers')

    # fig_scatter.circle(x='ws.time', y='ws.iat.us', fill_color="white", size=8, source=source_data_no_outliers, legend='data')

    # print('outliers: \n')
    # print(outliers)
    # print(len(data))
    # print(len(outliers))
    # print(f'outlier percentage: {len(outliers) * 100 / len(data)}')

    # Histogram - no outliers
    # stats['data_no_outliers'] = get_stats(data_no_outliers, 'ws.iat.us')
    # stats_df = pd.DataFrame(stats)
    # print(stats_df)

    # Create panel
    panel = models.widgets.Panel(child=fig_scatter, title='Outliers Analysis')
    return panel """


def panel_stats_outliers_removed(data: pd.DataFrame):
    """
    The `Statistics - Outliers Removed` panel which provides the comparison
    table with basic statistics for the original data and 
    - data with outliers removed using 1.5IQR, 3IQR, 5IQR, 10IQR fences,
    - data with outliers removed using 90th, 95th, 99th upper fence.

    Attributes:
        data:
            `pd.DataFrame` with packet inter-arrival times data preliminary
            cleaned up and consisting of the two columns `ws.time` and `ws.iat.us`,
            where `ws.time` is the packet timestamp in seconds and `ws.iat.us` is
            the corresponding inter-arrival time from the previous data packet
            in microseconds.

    Returns:
        `models.widgets.Panel` bokeh panel.
    """
    # Number of observations in original data
    n = len(data)

    # Calculate statistics and form the table for the data 
    # with outliers removed using 1.5IQR, 3IQR, 5IQR, 10IQR fences
    stats = {}
    stats['stats'] = [
        '25th percentile (Q1), us',
        '50th percentile (Median, Q2), us',
        '75th percentile (Q3), us',
        '90th percentile, us',
        '95th percentile, us',
        '99th percentile, us',
        'Interquartile range (IQR, Q3 - Q1), us',
        'Mean, us',
        'Standard deviation, us',
        'Min, us',
        'Max, us',
        'Packets',
        'Outliers',
        'Outliers, %',
    ]
    stats['original'] = get_stats(data['ws.iat.us'])
    stats['original'].extend([0, 0])

    multipliers = [1.5, 3, 5, 10]
    for multiplier in multipliers:
        data_no_outliers, outliers = remove_outliers(data, 'ws.iat.us', multiplier)
        stats[f'{multiplier} IQR'] = get_stats(data_no_outliers['ws.iat.us'])
        stats[f'{multiplier} IQR'].extend([len(outliers), round(len(outliers) * 100 / n, 2)])

    source = models.ColumnDataSource(pd.DataFrame(stats))
    columns = [
        models.widgets.TableColumn(field='stats', title='Statistic', width=500),
        models.widgets.TableColumn(field='original', title='Original Data'),
        models.widgets.TableColumn(field='1.5 IQR', title='Outliers Removed, 1.5 IQR'),
        models.widgets.TableColumn(field='3 IQR', title='Outliers Removed, 3 IQR'),
        models.widgets.TableColumn(field='5 IQR', title='Outliers Removed, 5 IQR'),
        models.widgets.TableColumn(field='10 IQR', title='Outliers Removed, 10 IQR'),
    ]
    table = models.widgets.DataTable(columns=columns, source=source, width=1100)

    # Calculate statistics and form the table for the data
    # with outliers removed using 90th, 95th, 99th upper fence
    stats_quantile = {}
    stats_quantile['stats'] = stats['stats']
    stats_quantile['original'] = stats['original']

    quantiles = [0.9, 0.95, 0.99]
    for quantile in quantiles:
        data_no_outliers, outliers = remove_outliers_by_quantile(data, 'ws.iat.us', quantile)
        stats_quantile[f'{quantile}'] = get_stats(data_no_outliers['ws.iat.us'])
        stats_quantile[f'{quantile}'].extend([len(outliers), round(len(outliers) * 100 / n, 2)])

    source_quantile = models.ColumnDataSource(pd.DataFrame(stats_quantile))
    columns_quantile = [
        models.widgets.TableColumn(field='stats', title='Statistic', width=500),
        models.widgets.TableColumn(field='original', title='Original Data', width=400),
        models.widgets.TableColumn(field='0.9', title='Outliers Removed, > 90th Percentile', width=400),
        models.widgets.TableColumn(field='0.95', title='Outliers Removed, > 95th Percentile', width=400),
        models.widgets.TableColumn(field='0.99', title='Outliers Removed, > 99th Percentile', width=400),
    ]
    table_quantile = models.widgets.DataTable(columns=columns_quantile, source=source_quantile, width=1100)

    # Create grid
    grid = layouts.gridplot(
        [
            [table, None],
            [table_quantile, None],
        ]
    )

    # Create panel
    panel = models.widgets.Panel(child=grid, title='Statistics - Outliers Removed')
    return panel


@click.command()
@click.argument(
    'path', 
    type=click.Path(exists=True)
)
@click.option(
    '--type',
    type=click.Choice(['data', 'probing']),
    default='data',
    help=   'Packet type to analyze: SRT DATA (all data packets including '
            'probing packets) or SRT DATA probing packets only.',
    show_default=True
)
def main(path, type):
    """
    This script parses tcpdump trace file captured at the receiver side
    and perform packet inter-arrival times analysis.
    """
    # Process tcpdump trace file and get SRT data packets only
    # (either all data packets or probing packets only)
    pcapng_filepath = pathlib.Path(path)	
    csv_filepath = convert.convert_to_csv(pcapng_filepath)
    srt_packets = extract_packets.extract_srt_packets(csv_filepath)

    if type == 'data':
        filename = 'all_packets_iat'
        title_prefix = 'All packets'
        packets = extract_packets.extract_data_packets(srt_packets)
    if type == 'probing':
        filename = 'probing_packets_iat'
        title_prefix = 'Probing packets'
        packets = extract_packets.extract_probing_packets(srt_packets)

    # Drop unneccassary for the following analysis columns
    packets = packets.loc[:, ['ws.time', 'ws.iat.us']]

    # Set output file for bokeh plots
    output_file(f'{filename}.html', title=f'{title_prefix} - Packet IAT analysis')

    panels = []
    panels.append(panel_eda(packets))
    panels.append(panel_stats_outliers_removed(packets))
    # panels.append(panel_scatter_plot(data))

    # Assign the panels to Tabs
    tabs = models.widgets.Tabs(tabs=panels)

    # Show the tabbed layout
    plotting.show(tabs)


if __name__ == '__main__':
    main()